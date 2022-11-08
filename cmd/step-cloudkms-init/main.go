package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // used to create the Subject Key Identifier by RFC 5280
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"go.step.sm/cli-utils/fileutil"
	"go.step.sm/cli-utils/ui"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/cloudkms"
	"go.step.sm/crypto/pemutil"
	"golang.org/x/crypto/ssh"
)

func main() {
	var credentialsFile string
	var project, location, ring string
	var protectionLevelName string
	var enableSSH bool
	flag.StringVar(&credentialsFile, "credentials-file", "", "Path to the `file` containing the Google's Cloud KMS credentials.")
	flag.StringVar(&project, "project", "", "Google Cloud Project ID.")
	flag.StringVar(&location, "location", "global", "Cloud KMS location name.")
	flag.StringVar(&ring, "ring", "pki", "Cloud KMS ring name.")
	flag.StringVar(&protectionLevelName, "protection-level", "SOFTWARE", "Protection level to use, SOFTWARE or HSM.")
	flag.BoolVar(&enableSSH, "ssh", false, "Create SSH keys.")
	flag.Usage = usage
	flag.Parse()

	switch {
	case project == "":
		usage()
	case location == "":
		fmt.Fprintln(os.Stderr, "flag `--location` is required")
		os.Exit(1)
	case ring == "":
		fmt.Fprintln(os.Stderr, "flag `--ring` is required")
		os.Exit(1)
	case protectionLevelName == "":
		fmt.Fprintln(os.Stderr, "flag `--protection-level` is required")
		os.Exit(1)
	}

	var protectionLevel apiv1.ProtectionLevel
	switch strings.ToUpper(protectionLevelName) {
	case "SOFTWARE":
		protectionLevel = apiv1.Software
	case "HSM":
		protectionLevel = apiv1.HSM
	default:
		fmt.Fprintf(os.Stderr, "invalid value `%s` for flag `--protection-level`; options are `SOFTWARE` or `HSM`\n", protectionLevelName)
		os.Exit(1)
	}

	// Initialize windows terminal
	ui.Init()

	ui.Println("⚠️  This command is deprecated and will be removed in future releases.")
	ui.Println("⚠️  Please use https://github.com/smallstep/step-kms-plugin instead.")

	c, err := cloudkms.New(context.Background(), apiv1.Options{
		Type:            apiv1.CloudKMS,
		CredentialsFile: credentialsFile,
	})
	if err != nil {
		fatal(err)
	}

	if err := createPKI(c, project, location, ring, protectionLevel); err != nil {
		fatal(err)
	}

	if enableSSH {
		ui.Println()
		if err := createSSH(c, project, location, ring, protectionLevel); err != nil {
			fatal(err)
		}
	}

	// Reset windows terminal
	ui.Reset()
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	ui.Reset()
	os.Exit(1)
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage: step-cloudkms-init --project <name>")
	fmt.Fprintln(os.Stderr, `
The step-cloudkms-init command initializes a public key infrastructure (PKI)
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

func createPKI(c *cloudkms.CloudKMS, project, location, keyRing string, protectionLevel apiv1.ProtectionLevel) error {
	ui.Println("Creating PKI ...")

	parent := "projects/" + project + "/locations/" + location + "/keyRings/" + keyRing + "/cryptoKeys"

	// Root Certificate
	resp, err := c.CreateKey(&apiv1.CreateKeyRequest{
		Name:               parent + "/root",
		SignatureAlgorithm: apiv1.ECDSAWithSHA256,
		ProtectionLevel:    protectionLevel,
	})
	if err != nil {
		return err
	}

	signer, err := c.CreateSigner(&resp.CreateSignerRequest)
	if err != nil {
		return err
	}

	now := time.Now()
	root := &x509.Certificate{
		IsCA:                  true,
		NotBefore:             now,
		NotAfter:              now.Add(time.Hour * 24 * 365 * 10),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
		Issuer:                pkix.Name{CommonName: "Smallstep Root"},
		Subject:               pkix.Name{CommonName: "Smallstep Root"},
		SerialNumber:          mustSerialNumber(),
		SubjectKeyId:          mustSubjectKeyID(resp.PublicKey),
		AuthorityKeyId:        mustSubjectKeyID(resp.PublicKey),
	}

	b, err := x509.CreateCertificate(rand.Reader, root, root, resp.PublicKey, signer)
	if err != nil {
		return err
	}

	if err := fileutil.WriteFile("root_ca.crt", pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: b,
	}), 0600); err != nil {
		return err
	}

	ui.PrintSelected("Root Key", resp.Name)
	ui.PrintSelected("Root Certificate", "root_ca.crt")

	root, err = pemutil.ReadCertificate("root_ca.crt")
	if err != nil {
		return err
	}

	// Intermediate Certificate
	resp, err = c.CreateKey(&apiv1.CreateKeyRequest{
		Name:               parent + "/intermediate",
		SignatureAlgorithm: apiv1.ECDSAWithSHA256,
		ProtectionLevel:    protectionLevel,
	})
	if err != nil {
		return err
	}

	intermediate := &x509.Certificate{
		IsCA:                  true,
		NotBefore:             now,
		NotAfter:              now.Add(time.Hour * 24 * 365 * 10),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		Issuer:                root.Subject,
		Subject:               pkix.Name{CommonName: "Smallstep Intermediate"},
		SerialNumber:          mustSerialNumber(),
		SubjectKeyId:          mustSubjectKeyID(resp.PublicKey),
	}

	b, err = x509.CreateCertificate(rand.Reader, intermediate, root, resp.PublicKey, signer)
	if err != nil {
		return err
	}

	if err := fileutil.WriteFile("intermediate_ca.crt", pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: b,
	}), 0600); err != nil {
		return err
	}

	ui.PrintSelected("Intermediate Key", resp.Name)
	ui.PrintSelected("Intermediate Certificate", "intermediate_ca.crt")

	return nil
}

func createSSH(c *cloudkms.CloudKMS, project, location, keyRing string, protectionLevel apiv1.ProtectionLevel) error {
	ui.Println("Creating SSH Keys ...")

	parent := "projects/" + project + "/locations/" + location + "/keyRings/" + keyRing + "/cryptoKeys"

	// User Key
	resp, err := c.CreateKey(&apiv1.CreateKeyRequest{
		Name:               parent + "/ssh-user-key",
		SignatureAlgorithm: apiv1.ECDSAWithSHA256,
		ProtectionLevel:    protectionLevel,
	})
	if err != nil {
		return err
	}

	key, err := ssh.NewPublicKey(resp.PublicKey)
	if err != nil {
		return err
	}

	if err := fileutil.WriteFile("ssh_user_ca_key.pub", ssh.MarshalAuthorizedKey(key), 0600); err != nil {
		return err
	}

	ui.PrintSelected("SSH User Public Key", "ssh_user_ca_key.pub")
	ui.PrintSelected("SSH User Private Key", resp.Name)

	// Host Key
	resp, err = c.CreateKey(&apiv1.CreateKeyRequest{
		Name:               parent + "/ssh-host-key",
		SignatureAlgorithm: apiv1.ECDSAWithSHA256,
		ProtectionLevel:    protectionLevel,
	})
	if err != nil {
		return err
	}

	key, err = ssh.NewPublicKey(resp.PublicKey)
	if err != nil {
		return err
	}

	if err := fileutil.WriteFile("ssh_host_ca_key.pub", ssh.MarshalAuthorizedKey(key), 0600); err != nil {
		return err
	}

	ui.PrintSelected("SSH Host Public Key", "ssh_host_ca_key.pub")
	ui.PrintSelected("SSH Host Private Key", resp.Name)

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
