package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/kms"
	"github.com/smallstep/certificates/kms/apiv1"
	"github.com/smallstep/certificates/kms/uri"
	"go.step.sm/cli-utils/fileutil"
	"go.step.sm/cli-utils/ui"
	"go.step.sm/crypto/pemutil"

	// Enable pkcs11.
	_ "github.com/smallstep/certificates/kms/pkcs11"
)

// Config is a mapping of the cli flags.
type Config struct {
	KMS              string
	RootOnly         bool
	RootObject       string
	RootKeyObject    string
	CrtObject        string
	CrtKeyObject     string
	SSHHostKeyObject string
	SSHUserKeyObject string
	RootFile         string
	KeyFile          string
	Pin              string
	NoCerts          bool
	EnableSSH        bool
	Force            bool
}

// Validate checks the flags in the config.
func (c *Config) Validate() error {
	switch {
	case c.KMS == "":
		return errors.New("flag `--kms` is required")
	case c.RootFile != "" && c.KeyFile == "":
		return errors.New("flag `--root` requires flag `--key`")
	case c.KeyFile != "" && c.RootFile == "":
		return errors.New("flag `--key` requires flag `--root`")
	case c.RootOnly && c.RootFile != "":
		return errors.New("flag `--root-only` is incompatible with flag `--root`")
	case c.RootFile == "" && c.RootObject == "":
		return errors.New("one of flag `--root` or `--root-cert` is required")
	case c.RootFile == "" && c.RootKeyObject == "":
		return errors.New("one of flag `--root` or `--root-key` is required")
	default:
		if c.RootFile != "" {
			c.RootObject = ""
			c.RootKeyObject = ""
		}
		if c.RootOnly {
			c.CrtObject = ""
			c.CrtKeyObject = ""
		}
		if !c.EnableSSH {
			c.SSHHostKeyObject = ""
			c.SSHUserKeyObject = ""
		}
		return nil
	}
}

func main() {
	var kmsuri string
	switch runtime.GOOS {
	case "darwin":
		kmsuri = "pkcs11:module-path=/usr/local/lib/pkcs11/yubihsm_pkcs11.dylib;token=YubiHSM"
	case "linux":
		kmsuri = "pkcs11:module-path=/usr/lib/x86_64-linux-gnu/pkcs11/yubihsm_pkcs11.so;token=YubiHSM"
	case "windows":
		if home, err := os.UserHomeDir(); err == nil {
			kmsuri = "pkcs11:module-path=" + home + "\\yubihsm2-sdk\\bin\\yubihsm_pkcs11.dll" + ";token=YubiHSM"
		}
	}

	var c Config
	flag.StringVar(&c.KMS, "kms", kmsuri, "PKCS #11 URI with the module-path and token to connect to the module.")
	flag.StringVar(&c.Pin, "pin", "", "PKCS #11 PIN")
	flag.StringVar(&c.RootObject, "root-cert", "pkcs11:id=7330;object=root-cert", "PKCS #11 URI with object id and label to store the root certificate.")
	flag.StringVar(&c.RootKeyObject, "root-key", "pkcs11:id=7330;object=root-key", "PKCS #11 URI with object id and label to store the root key.")
	flag.StringVar(&c.CrtObject, "crt-cert", "pkcs11:id=7331;object=intermediate-cert", "PKCS #11 URI with object id and label to store the intermediate certificate.")
	flag.StringVar(&c.CrtKeyObject, "crt-key", "pkcs11:id=7331;object=intermediate-key", "PKCS #11 URI with object id and label to store the intermediate certificate.")
	flag.StringVar(&c.SSHHostKeyObject, "ssh-host-key", "pkcs11:id=7332;object=ssh-host-key", "PKCS #11 URI with object id and label to store the key used to sign SSH host certificates.")
	flag.StringVar(&c.SSHUserKeyObject, "ssh-user-key", "pkcs11:id=7333;object=ssh-user-key", "PKCS #11 URI with object id and label to store the key used to sign SSH user certificates.")
	flag.BoolVar(&c.RootOnly, "root-only", false, "Store only only the root certificate and sign and intermediate.")
	flag.StringVar(&c.RootFile, "root", "", "Path to the root certificate to use.")
	flag.StringVar(&c.KeyFile, "key", "", "Path to the root key to use.")
	flag.BoolVar(&c.EnableSSH, "ssh", false, "Enable the creation of ssh keys.")
	flag.BoolVar(&c.NoCerts, "no-certs", false, "Do not store certificates in the module.")
	flag.BoolVar(&c.Force, "force", false, "Force the delete of previous keys.")
	flag.Usage = usage
	flag.Parse()

	if err := c.Validate(); err != nil {
		fatal(err)
	}

	u, err := uri.ParseWithScheme("pkcs11", c.KMS)
	if err != nil {
		fatal(err)
	}

	if u.Pin() == "" && c.Pin == "" {
		pin, err := ui.PromptPassword("What is the PKCS#11 PIN?")
		if err != nil {
			fatal(err)
		}
		c.Pin = string(pin)
	}

	k, err := kms.New(context.Background(), apiv1.Options{
		Type: string(apiv1.PKCS11),
		URI:  c.KMS,
		Pin:  c.Pin,
	})
	if err != nil {
		fatal(err)
	}

	defer func() {
		_ = k.Close()
	}()

	// Check if the slots are empty, fail if they are not
	certUris := []string{
		c.RootObject, c.CrtObject,
	}
	keyUris := []string{
		c.RootKeyObject, c.CrtKeyObject,
		c.SSHHostKeyObject, c.SSHUserKeyObject,
	}
	if !c.Force {
		for _, u := range certUris {
			if u != "" && !c.NoCerts {
				checkObject(k, u)
				checkCertificate(k, u)
			}
		}
		for _, u := range keyUris {
			if u != "" {
				checkObject(k, u)
			}
		}
	} else {
		deleter, ok := k.(interface {
			DeleteKey(uri string) error
			DeleteCertificate(uri string) error
		})
		if ok {
			for _, u := range certUris {
				if u != "" && !c.NoCerts {
					// Some HSMs like Nitrokey will overwrite the key with the
					// certificate label.
					if err := deleter.DeleteKey(u); err != nil {
						fatalClose(err, k)
					}
					if err := deleter.DeleteCertificate(u); err != nil {
						fatalClose(err, k)
					}
				}
			}
			for _, u := range keyUris {
				if u != "" {
					if err := deleter.DeleteKey(u); err != nil {
						fatalClose(err, k)
					}
				}
			}
		}
	}

	if err := createPKI(k, c); err != nil {
		fatalClose(err, k)
	}
}

func fatal(err error) {
	if os.Getenv("STEPDEBUG") == "1" {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
	} else {
		fmt.Fprintln(os.Stderr, err)
	}
	os.Exit(1)
}

func fatalClose(err error, k kms.KeyManager) {
	_ = k.Close()
	fatal(err)
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage: step-pkcs11-init")
	fmt.Fprintln(os.Stderr, `
The step-pkcs11-init command initializes a public key infrastructure (PKI)
to be used by step-ca.

This tool is experimental and in the future it will be integrated in step cli.

OPTIONS`)
	fmt.Fprintln(os.Stderr)
	flag.PrintDefaults()
	fmt.Fprintln(os.Stderr, `
COPYRIGHT

  (c) 2018-2021 Smallstep Labs, Inc.`)
	os.Exit(1)
}

func checkCertificate(k kms.KeyManager, rawuri string) {
	if cm, ok := k.(kms.CertificateManager); ok {
		if _, err := cm.LoadCertificate(&apiv1.LoadCertificateRequest{
			Name: rawuri,
		}); err == nil {
			fmt.Fprintf(os.Stderr, "⚠️  Your PKCS #11 module already has a certificate on %s.\n", rawuri)
			fmt.Fprintln(os.Stderr, "   If you want to delete it and start fresh, use `--force`.")
			_ = k.Close()
			os.Exit(1)
		}
	}
}

func checkObject(k kms.KeyManager, rawuri string) {
	if _, err := k.GetPublicKey(&apiv1.GetPublicKeyRequest{
		Name: rawuri,
	}); err == nil {
		fmt.Fprintf(os.Stderr, "⚠️  Your PKCS #11 module already has a key on %s.\n", rawuri)
		fmt.Fprintln(os.Stderr, "   If you want to delete it and start fresh, use `--force`.")
		_ = k.Close()
		os.Exit(1)
	}
}

func createPKI(k kms.KeyManager, c Config) error {
	var err error
	ui.Println("Creating PKI ...")
	now := time.Now()

	// Root Certificate
	var signer crypto.Signer
	var root *x509.Certificate
	if c.RootFile != "" && c.KeyFile != "" {
		root, err = pemutil.ReadCertificate(c.RootFile)
		if err != nil {
			return err
		}

		key, err := pemutil.Read(c.KeyFile)
		if err != nil {
			return err
		}

		var ok bool
		if signer, ok = key.(crypto.Signer); !ok {
			return errors.Errorf("key type '%T' does not implement a signer", key)
		}
	} else {
		resp, err := k.CreateKey(&apiv1.CreateKeyRequest{
			Name:               c.RootKeyObject,
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
		})
		if err != nil {
			return err
		}

		signer, err = k.CreateSigner(&resp.CreateSignerRequest)
		if err != nil {
			return err
		}

		template := &x509.Certificate{
			IsCA:                  true,
			NotBefore:             now,
			NotAfter:              now.Add(time.Hour * 24 * 365 * 10),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			MaxPathLen:            1,
			MaxPathLenZero:        false,
			Issuer:                pkix.Name{CommonName: "PKCS #11 Smallstep Root"},
			Subject:               pkix.Name{CommonName: "PKCS #11 Smallstep Root"},
			SerialNumber:          mustSerialNumber(),
			SubjectKeyId:          mustSubjectKeyID(resp.PublicKey),
			AuthorityKeyId:        mustSubjectKeyID(resp.PublicKey),
		}

		b, err := x509.CreateCertificate(rand.Reader, template, template, resp.PublicKey, signer)
		if err != nil {
			return err
		}

		root, err = x509.ParseCertificate(b)
		if err != nil {
			return errors.Wrap(err, "error parsing root certificate")
		}

		if cm, ok := k.(kms.CertificateManager); ok && !c.NoCerts {
			if err = cm.StoreCertificate(&apiv1.StoreCertificateRequest{
				Name:        c.RootObject,
				Certificate: root,
			}); err != nil {
				return err
			}
		}

		if err = fileutil.WriteFile("root_ca.crt", pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: b,
		}), 0600); err != nil {
			return err
		}

		ui.PrintSelected("Root Key", resp.Name)
		ui.PrintSelected("Root Certificate", "root_ca.crt")
	}

	// Intermediate Certificate
	var keyName string
	var publicKey crypto.PublicKey
	if c.RootOnly {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return errors.Wrap(err, "error creating intermediate key")
		}

		pass, err := ui.PromptPasswordGenerate("What do you want your password to be? [leave empty and we'll generate one]",
			ui.WithRichPrompt())
		if err != nil {
			return err
		}

		_, err = pemutil.Serialize(priv, pemutil.WithPassword(pass), pemutil.ToFile("intermediate_ca_key", 0600))
		if err != nil {
			return err
		}

		publicKey = priv.Public()
	} else {
		resp, err := k.CreateKey(&apiv1.CreateKeyRequest{
			Name:               c.CrtKeyObject,
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
		})
		if err != nil {
			return err
		}
		publicKey = resp.PublicKey
		keyName = resp.Name
	}

	template := &x509.Certificate{
		IsCA:                  true,
		NotBefore:             now,
		NotAfter:              now.Add(time.Hour * 24 * 365 * 10),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		Issuer:                root.Subject,
		Subject:               pkix.Name{CommonName: "YubiKey Smallstep Intermediate"},
		SerialNumber:          mustSerialNumber(),
		SubjectKeyId:          mustSubjectKeyID(publicKey),
	}

	b, err := x509.CreateCertificate(rand.Reader, template, root, publicKey, signer)
	if err != nil {
		return err
	}

	intermediate, err := x509.ParseCertificate(b)
	if err != nil {
		return errors.Wrap(err, "error parsing intermediate certificate")
	}

	if cm, ok := k.(kms.CertificateManager); ok && !c.NoCerts {
		if err = cm.StoreCertificate(&apiv1.StoreCertificateRequest{
			Name:        c.CrtObject,
			Certificate: intermediate,
		}); err != nil {
			return err
		}
	}

	if err = fileutil.WriteFile("intermediate_ca.crt", pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: b,
	}), 0600); err != nil {
		return err
	}

	if c.RootOnly {
		ui.PrintSelected("Intermediate Key", "intermediate_ca_key")
	} else {
		ui.PrintSelected("Intermediate Key", keyName)
	}

	ui.PrintSelected("Intermediate Certificate", "intermediate_ca.crt")

	if c.SSHHostKeyObject != "" {
		resp, err := k.CreateKey(&apiv1.CreateKeyRequest{
			Name:               c.SSHHostKeyObject,
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
		})
		if err != nil {
			return err
		}
		ui.PrintSelected("SSH Host Key", resp.Name)
	}

	if c.SSHUserKeyObject != "" {
		resp, err := k.CreateKey(&apiv1.CreateKeyRequest{
			Name:               c.SSHUserKeyObject,
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
		})
		if err != nil {
			return err
		}
		ui.PrintSelected("SSH User Key", resp.Name)
	}

	return nil
}

func mustSerialNumber() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	sn, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		panic(err)
	}
	return sn
}

func mustSubjectKeyID(key crypto.PublicKey) []byte {
	b, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		panic(err)
	}
	hash := sha1.Sum(b)
	return hash[:]
}
