package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	serviceAccountToken  = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	serviceAccountCACert = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// Client is minimal kubernetes client interface
type Client interface {
	Do(req *http.Request) (*http.Response, error)
	GetRequest(url string) (*http.Request, error)
	PostRequest(url, body, contentType string) (*http.Request, error)
	DeleteRequest(url string) (*http.Request, error)
	Host() string
}

type k8sClient struct {
	host       string
	token      string
	httpClient *http.Client
}

func (kc *k8sClient) GetRequest(url string) (*http.Request, error) {
	if !strings.HasPrefix(url, kc.host) {
		url = fmt.Sprintf("%s/%s", kc.host, url)
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if len(kc.token) > 0 {
		req.Header.Set("Authorization", "Bearer "+kc.token)
	}
	return req, nil
}

func (kc *k8sClient) PostRequest(url string, body string, contentType string) (*http.Request, error) {
	if !strings.HasPrefix(url, kc.host) {
		url = fmt.Sprintf("%s/%s", kc.host, url)
	}
	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	if len(kc.token) > 0 {
		req.Header.Set("Authorization", "Bearer "+kc.token)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return req, nil
}

func (kc *k8sClient) DeleteRequest(url string) (*http.Request, error) {
	if !strings.HasPrefix(url, kc.host) {
		url = fmt.Sprintf("%s/%s", kc.host, url)
	}
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return nil, err
	}
	if len(kc.token) > 0 {
		req.Header.Set("Authorization", "Bearer "+kc.token)
	}
	return req, nil
}

func (kc *k8sClient) Do(req *http.Request) (*http.Response, error) {
	return kc.httpClient.Do(req)
}

func (kc *k8sClient) Host() string {
	return kc.host
}

// NewInClusterK8sClient creates K8sClient if it is inside Kubernetes
func NewInClusterK8sClient() (Client, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if len(host) == 0 || len(port) == 0 {
		return nil, fmt.Errorf("unable to load in-cluster configuration, KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must be defined")
	}
	token, err := ioutil.ReadFile(serviceAccountToken)
	if err != nil {
		return nil, err
	}
	ca, err := ioutil.ReadFile(serviceAccountCACert)
	if err != nil {
		return nil, err
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(ca)
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS10,
		RootCAs:    certPool,
	}}
	httpClient := &http.Client{Transport: transport, Timeout: time.Nanosecond * 0}

	return &k8sClient{
		host:       "https://" + net.JoinHostPort(host, port),
		token:      string(token),
		httpClient: httpClient,
	}, nil
}
