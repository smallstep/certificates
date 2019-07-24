package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	"golang.org/x/crypto/ssh"
)

// SSHAuthority is the interface implemented by a SSH CA authority.
type SSHAuthority interface {
	SignSSH(key ssh.PublicKey, opts provisioner.SSHOptions, signOpts ...provisioner.SignOption) (*ssh.Certificate, error)
}

// SignSSHRequest is the request body of an SSH certificate request.
type SignSSHRequest struct {
	PublicKey   []byte       `json:"publicKey"` //base64 encoded
	OTT         string       `json:"ott"`
	CertType    string       `json:"certType"`
	Principals  []string     `json:"principals"`
	ValidAfter  TimeDuration `json:"validAfter"`
	ValidBefore TimeDuration `json:"validBefore"`
}

// SignSSHResponse is the response object that returns the SSH certificate.
type SignSSHResponse struct {
	Certificate SSHCertificate `json:"crt"`
}

// SSHCertificate represents the response SSH certificate.
type SSHCertificate struct {
	*ssh.Certificate
}

// MarshalJSON implements the json.Marshaler interface. The certificate is
// quoted string using the PEM encoding.
func (c SSHCertificate) MarshalJSON() ([]byte, error) {
	if c.Certificate == nil {
		return []byte("null"), nil
	}
	s := base64.StdEncoding.EncodeToString(c.Certificate.Marshal())
	return []byte(`"` + s + `"`), nil
}

// UnmarshalJSON implements the json.Unmarshaler interface. The certificate is
// expected to be a quoted string using the PEM encoding.
func (c *SSHCertificate) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return errors.Wrap(err, "error decoding certificate")
	}
	certData, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return errors.Wrap(err, "error decoding certificate")
	}
	pub, err := ssh.ParsePublicKey(certData)
	if err != nil {
		return errors.Wrap(err, "error decoding certificate")
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return errors.Errorf("error decoding certificate: %T is not an *ssh.Certificate", pub)
	}
	c.Certificate = cert
	return nil
}

// Validate validates the SignSSHRequest.
func (s *SignSSHRequest) Validate() error {
	switch {
	case s.CertType != "" && s.CertType != provisioner.SSHUserCert && s.CertType != provisioner.SSHHostCert:
		return errors.Errorf("unknown certType %s", s.CertType)
	case len(s.PublicKey) == 0:
		return errors.New("missing or empty publicKey")
	case len(s.OTT) == 0:
		return errors.New("missing or empty ott")
	default:
		return nil
	}
}

// ParsePublicKey returns the ssh.PublicKey from the request.
func (s *SignSSHRequest) ParsePublicKey() (ssh.PublicKey, error) {
	// Validate pub key.
	data := make([]byte, base64.StdEncoding.DecodedLen(len(s.PublicKey)))
	if _, err := base64.StdEncoding.Decode(data, s.PublicKey); err != nil {
		return nil, errors.Wrap(err, "error decoding publicKey")
	}

	// Trim padding from end of key.
	data = bytes.TrimRight(data, "\x00")
	publicKey, err := ssh.ParsePublicKey(data)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing publicKey")
	}

	return publicKey, nil
}

// SignSSH is an HTTP handler that reads an SignSSHRequest with a one-time-token
// (ott) from the body and creates a new SSH certificate with the information in
// the request.
func (h *caHandler) SignSSH(w http.ResponseWriter, r *http.Request) {
	var body SignSSHRequest
	if err := ReadJSON(r.Body, &body); err != nil {
		WriteError(w, BadRequest(errors.Wrap(err, "error reading request body")))
		return
	}

	logOtt(w, body.OTT)
	if err := body.Validate(); err != nil {
		WriteError(w, err)
		return
	}

	publicKey, err := body.ParsePublicKey()
	if err != nil {
		WriteError(w, BadRequest(err))
		return
	}

	opts := provisioner.SSHOptions{
		CertType:    body.CertType,
		Principals:  body.Principals,
		ValidBefore: body.ValidBefore,
		ValidAfter:  body.ValidAfter,
	}

	signOpts, err := h.Authority.AuthorizeSign(body.OTT)
	if err != nil {
		WriteError(w, Unauthorized(err))
		return
	}

	cert, err := h.Authority.SignSSH(publicKey, opts, signOpts...)
	if err != nil {
		WriteError(w, Forbidden(err))
		return
	}

	w.WriteHeader(http.StatusCreated)
	// logCertificate(w, cert)
	JSON(w, &SignSSHResponse{
		Certificate: SSHCertificate{cert},
	})
}
