package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/crypto/pemutil"
	"k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecs.UniversalDeserializer()
	// GetRootCAPath() is broken; points to secrets not certs. So
	// we'll hard code instead for now.
	//rootCAPath  = pki.GetRootCAPath()
	rootCAPath = "/home/step/.step/certs/root_ca.crt"
)

const (
	admissionWebhookAnnotationKey         = "autocert.step.sm/name"
	admissionWebhookStatusKey             = "autocert.step.sm/status"
	provisionerPasswordFile               = "/home/step/password/password"
	volumeMountPath                       = "/var/run/autocert.step.sm"
	tokenSecretKey                        = "token"
	tokenSecretLabel                      = "autocert.step.sm/token"
	clusterDomain                         = "cluster.local"
)

// Config options for the autocert admission controller.
type Config struct {
	LogFormat    string           `yaml:"logFormat"`
	CaURL        string           `yaml:"caUrl"`
	CertLifetime string           `yaml:"certLifetime"`
	Bootstrapper corev1.Container `yaml:"bootstrapper"`
	Renewer      corev1.Container `yaml:"renewer"`
	CertsVolume  corev1.Volume    `yaml:"certsVolume"`
}

// PatchOperation represents a RFC6902 JSONPatch Operation
type PatchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

// RFC6901 JSONPath Escaping -- https://tools.ietf.org/html/rfc6901
func escapeJSONPath(path string) string {
	// Replace`~` with `~0` then `/` with `~1`. Note that the order
	// matters otherwise we'll turn a `/` into a `~/`.
	path = strings.Replace(path, "~", "~0", -1)
	path = strings.Replace(path, "/", "~1", -1)
	return path
}

func loadConfig(file string) (*Config, error) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// createTokenSecret generates a kubernetes Secret object containing a bootstrap token
// in the specified namespce. The secret name is randomly generated with a given prefix.
// A goroutine is scheduled to cleanup the secret after the token expires. The secret
// is also labelled for easy identification and manual cleanup.
func createTokenSecret(prefix, namespace, token string) (string, error) {
	secret := corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: prefix,
			Namespace:    namespace,
			Labels: map[string]string{
				tokenSecretLabel: "true",
			},
		},
		StringData: map[string]string{
			tokenSecretKey: token,
		},
		Type: corev1.SecretTypeOpaque,
	}

	client, err := NewInClusterK8sClient()
	if err != nil {
		return "", err
	}

	body, err := json.Marshal(secret)
	if err != nil {
		return "", err
	}
	log.WithField("secret", string(body)).Debug("Creating secret")

	req, err := client.PostRequest(fmt.Sprintf("api/v1/namespaces/%s/secrets", namespace), string(body), "application/json")
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Errorf("Secret creation error. Response: %v", resp)
		return "", errors.Wrap(err, "secret creation")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Errorf("Secret creation error (!2XX). Response: %v", resp)
		var rbody []byte
		if resp.Body != nil {
			if data, err := ioutil.ReadAll(resp.Body); err == nil {
				rbody = data
			}
		}
		log.Error("Error body: ", string(rbody))
		return "", errors.New("Not 200")
	}

	var rbody []byte
	if resp.Body != nil {
		if data, err := ioutil.ReadAll(resp.Body); err == nil {
			rbody = data
		}
	}
	if len(rbody) == 0 {
		return "", errors.New("Empty response body")
	}

	var created *corev1.Secret
	if err := json.Unmarshal(rbody, &created); err != nil {
		return "", errors.Wrap(err, "Error unmarshalling secret response")
	}

	// Clean up after ourselves by deleting the Secret after the bootstrap
	// token expires. This is best effort -- obviously we'll miss some stuff
	// if this process goes away -- but the secrets are also labelled so
	// it's also easy to clean them up in bulk using kubectl if we miss any.
	go func() {
		time.Sleep(tokenLifetime)
		req, err := client.DeleteRequest(fmt.Sprintf("api/v1/namespaces/%s/secrets/%s", namespace, created.Name))
		ctxLog := log.WithFields(log.Fields{
			"name":      created.Name,
			"namespace": namespace,
		})
		if err != nil {
			ctxLog.WithField("error", err).Error("Error deleting expired boostrap token secret")
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			ctxLog.WithField("error", err).Error("Error deleting expired boostrap token secret")
			return
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			ctxLog.WithFields(log.Fields{
				"status":     resp.Status,
				"statusCode": resp.StatusCode,
			}).Error("Error deleting expired boostrap token secret")
			return
		}
		ctxLog.Info("Deleted expired bootstrap token secret")
	}()

	return created.Name, err
}

// mkBootstrapper generates a bootstrap container based on the template defined in Config. It
// generates a new bootstrap token and mounts it, along with other required coniguration, as
// environment variables in the returned bootstrap container.
func mkBootstrapper(config *Config, commonName string, namespace string, provisioner Provisioner) (corev1.Container, error) {
	b := config.Bootstrapper

	token, err := provisioner.Token(commonName)
	if err != nil {
		return b, errors.Wrap(err, "token generation")
	}

	// Generate CA fingerprint
	crt, err := pemutil.ReadCertificate(rootCAPath)
	if err != nil {
		return b, errors.Wrap(err, "CA fingerprint")
	}
	sum := sha256.Sum256(crt.Raw)
	fingerprint := strings.ToLower(hex.EncodeToString(sum[:]))

	secretName, err := createTokenSecret(commonName+"-", namespace, token)
	if err != nil {
		return b, errors.Wrap(err, "create token secret")
	}
	log.Infof("Secret name is: %s", secretName)


	b.Env = append(b.Env, corev1.EnvVar{
		Name:  "COMMON_NAME",
		Value: commonName,
	})

	b.Env = append(b.Env, corev1.EnvVar{
		Name: "STEP_TOKEN",
		ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: secretName,
				},
				Key: tokenSecretKey,
			},
		},
	})
	b.Env = append(b.Env, corev1.EnvVar{
		Name:  "STEP_CA_URL",
		Value: config.CaURL,
	})
	b.Env = append(b.Env, corev1.EnvVar{
		Name:  "STEP_FINGERPRINT",
		Value: fingerprint,
	})
	b.Env = append(b.Env, corev1.EnvVar{
		Name:  "STEP_NOT_AFTER",
		Value: config.CertLifetime,
	})
	return b, nil
}

// mkRenewer generates a new renewer based on the template provided in Config.
func mkRenewer(config *Config) corev1.Container {
	r := config.Renewer
	r.Env = append(r.Env, corev1.EnvVar{
		Name:  "STEP_CA_URL",
		Value: config.CaURL,
	})
	return r
}

func addContainers(existing, new []corev1.Container, path string) (ops []PatchOperation) {
	if len(existing) == 0 {
		return []PatchOperation{
			{
				Op:    "add",
				Path:  path,
				Value: new,
			},
		}
	}

	for _, add := range new {
		ops = append(ops, PatchOperation{
			Op:    "add",
			Path:  path + "/-",
			Value: add,
		})
	}
	return ops
}

func addVolumes(existing, new []corev1.Volume, path string) (ops []PatchOperation) {
	if len(existing) == 0 {
		return []PatchOperation{
			{
				Op:    "add",
				Path:  path,
				Value: new,
			},
		}
	}

	for _, add := range new {
		ops = append(ops, PatchOperation{
			Op:    "add",
			Path:  path + "/-",
			Value: add,
		})
	}
	return ops
}

func addCertsVolumeMount(volumeName string, containers []corev1.Container) (ops []PatchOperation) {
	volumeMount := corev1.VolumeMount{
		Name:      volumeName,
		MountPath: volumeMountPath,
		ReadOnly:  true,
	}
	for i, container := range containers {
		if len(container.VolumeMounts) == 0 {
			ops = append(ops, PatchOperation{
				Op:    "add",
				Path:  fmt.Sprintf("/spec/containers/%v/volumeMounts", i),
				Value: []corev1.VolumeMount{volumeMount},
			})
		} else {
			ops = append(ops, PatchOperation{
				Op:    "add",
				Path:  fmt.Sprintf("/spec/containers/%v/volumeMounts/-", i),
				Value: volumeMount,
			})
		}
	}
	return ops
}

func addAnnotations(existing, new map[string]string) (ops []PatchOperation) {
	if len(existing) == 0 {
		return []PatchOperation{
			{
				Op:    "add",
				Path:  "/metadata/annotations",
				Value: new,
			},
		}
	}
	for k, v := range new {
		if existing[k] == "" {
			ops = append(ops, PatchOperation{
				Op:    "add",
				Path:  "/metadata/annotations/" + escapeJSONPath(k),
				Value: v,
			})
		} else {
			ops = append(ops, PatchOperation{
				Op:    "replace",
				Path:  "/metadata/annotations/" + escapeJSONPath(k),
				Value: v,
			})
		}
	}
	return ops
}

// patch produces a list of patches to apply to a pod to inject a certificate. In particular,
// we patch the pod in order to:
//  - Mount the `certs` volume in existing containers defined in the pod
//  - Add the autocert-renewer as a container (a sidecar)
//  - Add the autocert-bootstrapper as an initContainer
//  - Add the `certs` volume definition
//  - Annotate the pod to indicate that it's been processed by this controller
// The result is a list of serialized JSONPatch objects (or an error).
func patch(pod *corev1.Pod, namespace string, config *Config, provisioner Provisioner) ([]byte, error) {
	var ops []PatchOperation

	annotations := pod.ObjectMeta.GetAnnotations()
	commonName := annotations[admissionWebhookAnnotationKey]
	renewer := mkRenewer(config)
	bootstrapper, err := mkBootstrapper(config, commonName, namespace, provisioner)
	if err != nil {
		return nil, err
	}

	ops = append(ops, addCertsVolumeMount(config.CertsVolume.Name, pod.Spec.Containers)...)
	ops = append(ops, addContainers(pod.Spec.Containers, []corev1.Container{renewer}, "/spec/containers")...)
	ops = append(ops, addContainers(pod.Spec.InitContainers, []corev1.Container{bootstrapper}, "/spec/initContainers")...)
	ops = append(ops, addVolumes(pod.Spec.Volumes, []corev1.Volume{config.CertsVolume}, "/spec/volumes")...)
	ops = append(ops, addAnnotations(pod.Annotations, map[string]string{admissionWebhookStatusKey: "injected"})...)

	return json.Marshal(ops)
}

// shouldMutate checks whether a pod is subject to mutation by this admission controller. A pod
// is subject to mutation if it's annotated with the `admissionWebhookAnnotationKey` and if it
// has not already been processed (indicated by `admissionWebhookStatusKey` set to `injected`).
func shouldMutate(metadata *metav1.ObjectMeta, namespace string) bool {
	annotations := metadata.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}

	// Only mutate if the object is annotated appropriately (annotation key set) and we haven't
	// mutated already (status key isn't set).
	if annotations[admissionWebhookAnnotationKey] == "" || annotations[admissionWebhookStatusKey] == "injected" {
		return false
	}

	subject := strings.Trim(annotations[admissionWebhookAnnotationKey], ".")
	subjectParts := strings.Split(subject, ".")
	clusterDomainParts := strings.Split(fmt.Sprintf("svc.%s", clusterDomain), ".")

	// Mutate if subject is a lonely hostname, e.g., "example", or
	// if it is two parts. While this could be a hostname + namespace,
	// it could also be a regular domain (e.g., `example.com`). We don't
	// want to preclude users from issuing non-cluster hostnames, so we
	// allow it. Additionally, if it is greater than 5 parts, it is not
	// a cluster hostname.
	if len(subjectParts) < 3  || len(subjectParts) > 5 {
		return true
	}

	// Check if the parts of the domain match the cluster domain, if they don't
	// it's not a cluster hostname and we can safely sign it.
	for index, part := range clusterDomainParts {
		if len(subjectParts) - 2 > index && subjectParts[index + 2] != part {
			return true
		}
	}

	// If the namespace is not the same as our pod's namespace, do not mutate the pod.
	if subjectParts[1] != namespace {
		log.WithField("namespace", namespace).WithField("subject", subject).Infof("Invalid subject for pod in namespace.")
		return false
	}

	return true
}

// mutate takes an `AdmissionReview`, determines whether it is subject to mutation, and returns
// an appropriate `AdmissionResponse` including patches or any errors that occurred.
func mutate(review *v1beta1.AdmissionReview, config *Config, provisioner Provisioner) *v1beta1.AdmissionResponse {
	ctxLog := log.WithField("uid", review.Request.UID)

	request := review.Request
	var pod corev1.Pod
	if err := json.Unmarshal(request.Object.Raw, &pod); err != nil {
		ctxLog.WithField("error", err).Error("Error unmarshalling pod")
		return &v1beta1.AdmissionResponse{
			Allowed: false,
			UID:     request.UID,
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	ctxLog = ctxLog.WithFields(log.Fields{
		"kind":         request.Kind,
		"operation":    request.Operation,
		"name":         pod.Name,
		"generateName": pod.GenerateName,
		"namespace":    request.Namespace,
		"user":         request.UserInfo,
	})

	if !shouldMutate(&pod.ObjectMeta, request.Namespace) {
		ctxLog.WithField("annotations", pod.Annotations).Info("Skipping mutation")
		return &v1beta1.AdmissionResponse{
			Allowed: true,
			UID:     request.UID,
		}
	}

	patchBytes, err := patch(&pod, request.Namespace, config, provisioner)
	if err != nil {
		ctxLog.WithField("error", err).Error("Error generating patch")
		return &v1beta1.AdmissionResponse{
			Allowed: false,
			UID:     request.UID,
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	ctxLog.WithField("patch", string(patchBytes)).Info("Generated patch")
	return &v1beta1.AdmissionResponse{
		Allowed: true,
		Patch:   patchBytes,
		UID:     request.UID,
		PatchType: func() *v1beta1.PatchType {
			pt := v1beta1.PatchTypeJSONPatch
			return &pt
		}(),
	}
}

func main() {
	if len(os.Args) != 2 {
		log.Errorf("Usage: %s <config>\n", os.Args[0])
		os.Exit(1)
	}

	config, err := loadConfig(os.Args[1])
	if err != nil {
		panic(err)
	}

	log.SetOutput(os.Stdout)
	if config.LogFormat == "json" {
		log.SetFormatter(&log.JSONFormatter{})
	}
	if config.LogFormat == "text" {
		log.SetFormatter(&log.TextFormatter{})
	}

	log.WithFields(log.Fields{
		"config": config,
	}).Info("Loaded config")

	provisionerName := os.Getenv("PROVISIONER_NAME")
	provisionerKid := os.Getenv("PROVISIONER_KID")
	log.WithFields(log.Fields{
		"provisionerName": provisionerName,
		"provisionerKid":  provisionerKid,
	}).Info("Loaded provisioner configuration")

	provisioner, err := NewProvisioner(provisionerName, provisionerKid, config.CaURL, rootCAPath, provisionerPasswordFile)
	if err != nil {
		log.Errorf("Error loading provisioner: %v", err)
		os.Exit(1)
	}
	log.WithFields(log.Fields{
		"name": provisioner.Name(),
		"kid":  provisioner.Kid(),
	}).Info("Loaded provisioner")

	namespace := os.Getenv("NAMESPACE")
	if namespace == "" {
		log.Errorf("$NAMESPACE not set")
		os.Exit(1)
	}

	name := fmt.Sprintf("autocert.%s.svc", namespace)
	token, err := provisioner.Token(name)
	if err != nil {
		log.WithField("error", err).Errorf("Error generating bootstrap token during controller startup")
		os.Exit(1)
	}
	log.WithField("name", name).Infof("Generated bootstrap token for controller")

	// make sure to cancel the renew goroutine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := ca.BootstrapServer(ctx, token, &http.Server{
		Addr: ":4443",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/healthz" {
				log.Info("/healthz")
				fmt.Fprintf(w, "ok")
				w.WriteHeader(http.StatusOK)
				return
			}

			/*
				var name string
				if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
					name = r.TLS.PeerCertificates[0].Subject.CommonName
				}
			*/

			if r.URL.Path != "/mutate" {
				log.WithField("path", r.URL.Path).Error("Bad Request: 404 Not Found")
				http.NotFound(w, r)
				return
			}

			var body []byte
			if r.Body != nil {
				if data, err := ioutil.ReadAll(r.Body); err == nil {
					body = data
				}
			}
			if len(body) == 0 {
				log.Error("Bad Request: 400 (Empty Body)")
				http.Error(w, "Bad Request (Empty Body)", http.StatusBadRequest)
				return
			}

			contentType := r.Header.Get("Content-Type")
			if contentType != "application/json" {
				log.WithField("Content-Type", contentType).Error("Bad Request: 415 (Unsupported Media Type)")
				http.Error(w, fmt.Sprintf("Bad Request: 415 Unsupported Media Type (Expected Content-Type 'application/json' but got '%s')", contentType), http.StatusUnsupportedMediaType)
				return
			}

			var response *v1beta1.AdmissionResponse
			review := v1beta1.AdmissionReview{}
			if _, _, err := deserializer.Decode(body, nil, &review); err != nil {
				log.WithFields(log.Fields{
					"body":  body,
					"error": err,
				}).Error("Can't decode body")
				response = &v1beta1.AdmissionResponse{
					Allowed: false,
					Result: &metav1.Status{
						Message: err.Error(),
					},
				}
			} else {
				response = mutate(&review, config, provisioner)
			}

			resp, err := json.Marshal(v1beta1.AdmissionReview{
				Response: response,
			})
			if err != nil {
				log.WithFields(log.Fields{
					"uid":   review.Request.UID,
					"error": err,
				}).Info("Marshal error")
				http.Error(w, fmt.Sprintf("Marshal Error: %v", err), http.StatusInternalServerError)
			} else {
				log.WithFields(log.Fields{
					"uid":      review.Request.UID,
					"response": string(resp),
				}).Info("Returning review")
				if _, err := w.Write(resp); err != nil {
					log.WithFields(log.Fields{
						"uid":   review.Request.UID,
						"error": err,
					}).Info("Write error")
				}
			}
		}),
	}, ca.VerifyClientCertIfGiven())
	if err != nil {
		panic(err)
	}

	log.Info("Listening on :4443 ...")
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		panic(err)
	}
}
