package x509util

import (
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"math/big"
	"net"
	"net/url"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/x509util"
)

// SplitSANs splits a slice of Subject Alternative Names into slices of
// IP Addresses and DNS Names. If an element is not an IP address, then it
// is bucketed as a DNS Name.
func SplitSANs(sans []string) (dnsNames []string, ips []net.IP, emails []string, uris []*url.URL) {
	return x509util.SplitSANs(sans)
}

func CreateSANs(sans []string) []SubjectAlternativeName {
	dnsNames, ips, emails, uris := SplitSANs(sans)
	sanTypes := make([]SubjectAlternativeName, 0, len(sans))
	for _, v := range dnsNames {
		sanTypes = append(sanTypes, SubjectAlternativeName{Type: "dns", Value: v})
	}
	for _, v := range ips {
		sanTypes = append(sanTypes, SubjectAlternativeName{Type: "ip", Value: v.String()})
	}
	for _, v := range emails {
		sanTypes = append(sanTypes, SubjectAlternativeName{Type: "email", Value: v})
	}
	for _, v := range uris {
		sanTypes = append(sanTypes, SubjectAlternativeName{Type: "uri", Value: v.String()})
	}
	return sanTypes
}

func CreateTemplateData(commonName string, sans []string) TemplateData {
	return TemplateData{
		SubjectKey: Subject{
			CommonName: commonName,
		},
		SANsKey: CreateSANs(sans),
	}
}

// generateSerialNumber returns a random serial number.
func generateSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	sn, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, errors.Wrap(err, "error generating serial number")
	}
	return sn, nil
}

func generateSubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling public key")
	}
	hash := sha1.Sum(b)
	return hash[:], nil
}
