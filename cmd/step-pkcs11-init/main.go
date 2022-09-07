package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // used to create the Subject Key Identifier by RFC 5280
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
	"go.step.sm/cli-utils/fileutil"
	"go.step.sm/cli-utils/ui"
	"go.step.sm/crypto/kms"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/uri"
	"go.step.sm/crypto/pemutil"

	// Enable pkcs11.
	_ "go.step.sm/crypto/kms/pkcs11"
)

// Config is a mapping of the cli flags.
type Config struct {
	KMS              string
	GenerateRoot     bool
	RootObject       string
	RootKeyObject    string
	RootSubject      string
	RootPath         string
	CrtObject        string
	CrtPath          string
	CrtKeyObject     string
	CrtSubject       string
	CrtKeyPath       string
	SSHHostKeyObject string
	SSHUserKeyObject string
	RootFile         string
	KeyFile          string
	Pin              string
	PinFile          string
	NoCerts          bool
	EnableSSH        bool
	Force            bool
	Extractable      bool
}

// Validate checks the flags in the config.
func (c *Config) Validate() error {
	switch {
	case c.KMS == "":
		return errors.New("flag `--kms` is required")
	case c.CrtPath == "":
		return errors.New("flag `--crt-cert-path` is required")
	case c.RootFile != "" && c.KeyFile == "":
		return errors.New("flag `--root-cert-file` requires flag `--root-key-file`")
	case c.KeyFile != "" && c.RootFile == "":
		return errors.New("flag `--root-key-file` requires flag `--root-cert-file`")
	case c.RootFile == "" && c.RootObject == "":
		return errors.New("one of flag `--root-cert-file` or `--root-cert-obj` is required")
	case c.KeyFile == "" && c.RootKeyObject == "":
		return errors.New("one of flag `--root-key-file` or `--root-key-obj` is required")
	case c.CrtKeyPath == "" && c.CrtKeyObject == "":
		return errors.New("one of flag `--crt-key-path` or `--crt-key-obj` is required")
	case c.RootFile == "" && c.GenerateRoot && c.RootKeyObject == "":
		return errors.New("flag `--root-gen` requires flag `--root-key-obj`")
	case c.RootFile == "" && c.GenerateRoot && c.RootPath == "":
		return errors.New("flag `--root-gen` requires `--root-cert-path`")
	case c.Pin != "" && c.PinFile != "":
		return errors.New("Only set one of pin and pin-file")
	default:
		if c.RootFile != "" {
			c.GenerateRoot = false
			c.RootObject = ""
			c.RootKeyObject = ""
		}
		if c.CrtKeyPath != "" {
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
	flag.StringVar(&c.PinFile, "pin-file", "", "PKCS #11 PIN File")
	// Option 1: Generate new root
	flag.BoolVar(&c.GenerateRoot, "root-gen", true, "Enable the generation of a root key.")
	flag.StringVar(&c.RootSubject, "root-name", "PKCS #11 Smallstep Root", "Subject and Issuer of the root certificate.")
	flag.StringVar(&c.RootObject, "root-cert-obj", "pkcs11:id=7330;object=root-cert", "PKCS #11 URI with object id and label to store the root certificate.")
	flag.StringVar(&c.RootKeyObject, "root-key-obj", "pkcs11:id=7330;object=root-key", "PKCS #11 URI with object id and label to store the root key.")
	// Option 2: Read root from disk and sign intermediate
	flag.StringVar(&c.RootFile, "root-cert-file", "", "Path to the root certificate to use.")
	flag.StringVar(&c.KeyFile, "root-key-file", "", "Path to the root key to use.")
	// Option 3: Generate certificate signing request
	flag.StringVar(&c.CrtSubject, "crt-name", "PKCS #11 Smallstep Intermediate", "Subject of the intermediate certificate.")
	flag.StringVar(&c.CrtObject, "crt-cert-obj", "pkcs11:id=7331;object=intermediate-cert", "PKCS #11 URI with object id and label to store the intermediate certificate.")
	flag.StringVar(&c.CrtKeyObject, "crt-key-obj", "pkcs11:id=7331;object=intermediate-key", "PKCS #11 URI with object id and label to store the intermediate certificate.")
	// SSH certificates
	flag.BoolVar(&c.EnableSSH, "ssh", false, "Enable the creation of ssh keys.")
	flag.StringVar(&c.SSHHostKeyObject, "ssh-host-key", "pkcs11:id=7332;object=ssh-host-key", "PKCS #11 URI with object id and label to store the key used to sign SSH host certificates.")
	flag.StringVar(&c.SSHUserKeyObject, "ssh-user-key", "pkcs11:id=7333;object=ssh-user-key", "PKCS #11 URI with object id and label to store the key used to sign SSH user certificates.")
	// Output files
	flag.StringVar(&c.RootPath, "root-cert-path", "root_ca.crt", "Location to write the root certificate.")
	flag.StringVar(&c.CrtPath, "crt-cert-path", "intermediate_ca.crt", "Location to write the intermediate certificate.")
	flag.StringVar(&c.CrtKeyPath, "crt-key-path", "", "Location to write the intermediate private key.")
	// Others
	flag.BoolVar(&c.NoCerts, "no-certs", false, "Do not store certificates in the module.")
	flag.BoolVar(&c.Force, "force", false, "Force the delete of previous keys.")
	flag.BoolVar(&c.Extractable, "extractable", false, "Allow export of private keys under wrap.")
	flag.Usage = usage
	flag.Parse()

	if err := c.Validate(); err != nil {
		fatal(err)
	}

	u, err := uri.ParseWithScheme("pkcs11", c.KMS)
	if err != nil {
		fatal(err)
	}

	// Initialize windows terminal
	ui.Init()

	ui.Println("⚠️  This command is deprecated and will be removed in future releases.")
	ui.Println("⚠️  Please use https://github.com/smallstep/step-kms-plugin instead.")

	switch {
	case u.Get("pin-value") != "":
	case u.Get("pin-source") != "":
	case c.Pin != "":
	case c.PinFile != "":
		content, err := os.ReadFile(c.PinFile)
		if err != nil {
			fatal(err)
		}
		c.Pin = string(content)

	default:
		pin, err := ui.PromptPassword("What is the PKCS#11 PIN?")
		if err != nil {
			fatal(err)
		}
		c.Pin = string(pin)
	}

	k, err := kms.New(context.Background(), apiv1.Options{
		Type: apiv1.PKCS11,
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

	// Reset windows terminal
	ui.Reset()
}

func fatal(err error) {
	if os.Getenv("STEPDEBUG") == "1" {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
	} else {
		fmt.Fprintln(os.Stderr, err)
	}
	ui.Reset()
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
	fmt.Fprintf(os.Stderr, `
COPYRIGHT

  (c) 2018-%d Smallstep Labs, Inc.
`, time.Now().Year())
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
	switch {
	case c.GenerateRoot:
		resp, err := k.CreateKey(&apiv1.CreateKeyRequest{
			Name:               c.RootKeyObject,
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
			Extractable:        c.Extractable,
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
			Issuer:                pkix.Name{CommonName: c.RootSubject},
			Subject:               pkix.Name{CommonName: c.RootSubject},
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

		if cm, ok := k.(kms.CertificateManager); ok && c.RootObject != "" && !c.NoCerts {
			if err := cm.StoreCertificate(&apiv1.StoreCertificateRequest{
				Name:        c.RootObject,
				Certificate: root,
				Extractable: c.Extractable,
			}); err != nil {
				return err
			}
		} else {
			c.RootObject = ""
		}

		if err := fileutil.WriteFile(c.RootPath, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: b,
		}), 0600); err != nil {
			return err
		}

		ui.PrintSelected("Root Key", resp.Name)
		ui.PrintSelected("Root Certificate", c.RootPath)
		if c.RootObject != "" {
			ui.PrintSelected("Root Certificate Object", c.RootObject)
		}
	case c.RootFile != "" && c.KeyFile != "": // Read Root From File
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
	}

	// Intermediate Certificate
	var keyName string
	var publicKey crypto.PublicKey
	var intSigner crypto.Signer
	if c.CrtKeyPath != "" {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return errors.Wrap(err, "error creating intermediate key")
		}

		pass, err := ui.PromptPasswordGenerate("What do you want your password to be? [leave empty and we'll generate one]",
			ui.WithRichPrompt())
		if err != nil {
			return err
		}

		_, err = pemutil.Serialize(priv, pemutil.WithPassword(pass), pemutil.ToFile(c.CrtKeyPath, 0600))
		if err != nil {
			return err
		}

		publicKey = priv.Public()
		intSigner = priv
	} else {
		resp, err := k.CreateKey(&apiv1.CreateKeyRequest{
			Name:               c.CrtKeyObject,
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
			Extractable:        c.Extractable,
		})
		if err != nil {
			return err
		}
		publicKey = resp.PublicKey
		keyName = resp.Name

		intSigner, err = k.CreateSigner(&resp.CreateSignerRequest)
		if err != nil {
			return err
		}
	}

	if root != nil {
		template := &x509.Certificate{
			IsCA:                  true,
			NotBefore:             now,
			NotAfter:              now.Add(time.Hour * 24 * 365 * 10),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			MaxPathLen:            0,
			MaxPathLenZero:        true,
			Issuer:                root.Subject,
			Subject:               pkix.Name{CommonName: c.CrtSubject},
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

		if cm, ok := k.(kms.CertificateManager); ok && c.CrtObject != "" && !c.NoCerts {
			if err := cm.StoreCertificate(&apiv1.StoreCertificateRequest{
				Name:        c.CrtObject,
				Certificate: intermediate,
				Extractable: c.Extractable,
			}); err != nil {
				return err
			}
		} else {
			c.CrtObject = ""
		}

		if err := fileutil.WriteFile(c.CrtPath, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: b,
		}), 0600); err != nil {
			return err
		}
	} else {
		// No root available, generate CSR for external root.
		csrTemplate := x509.CertificateRequest{
			Subject:            pkix.Name{CommonName: c.CrtSubject},
			SignatureAlgorithm: x509.ECDSAWithSHA256,
		}
		// step: generate the csr request
		csrCertificate, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, intSigner)
		if err != nil {
			return err
		}
		if err := fileutil.WriteFile(c.CrtPath, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrCertificate,
		}), 0600); err != nil {
			return err
		}
	}

	if c.CrtKeyPath != "" {
		ui.PrintSelected("Intermediate Key", c.CrtKeyPath)
	} else {
		ui.PrintSelected("Intermediate Key", keyName)
	}

	if root != nil {
		ui.PrintSelected("Intermediate Certificate", c.CrtPath)
		if c.CrtObject != "" {
			ui.PrintSelected("Intermediate Certificate Object", c.CrtObject)
		}
	} else {
		ui.PrintSelected("Intermediate Certificate Request", c.CrtPath)
	}

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
	//nolint:gosec // used to create the Subject Key Identifier by RFC 5280
	hash := sha1.Sum(b)
	return hash[:]
}
