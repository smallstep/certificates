package api

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority"
)

func (h *Handler) RevokeCert(w http.ResponseWriter, r *http.Request) {

	// TODO: support the non-kid case, i.e. JWK with the public key of the cert
	// base the account + certificate JWK instead of the kid (which is now the case)
	// TODO: handle errors; sent the right ACME response back

	ctx := r.Context()
	_, err := accountFromContext(ctx)
	if err != nil {
		api.WriteError(w, err)
		return
	}

	// TODO: do checks on account, i.e. is it still valid? is it allowed to do revocations? Revocations on the to be revoked cert?

	_, err = provisionerFromContext(ctx)
	if err != nil {
		fmt.Println(err)
	}

	// TODO: let provisioner authorize the revocation? Necessary per provisioner? Or can it be done by the CA, like the Revoke itself.

	p, err := payloadFromContext(ctx)
	if err != nil {
		fmt.Println(err)
	}

	type revokedCert struct {
		Certificate string `json:"certificate"`
		Reason      int    `json:"reason"` // TODO: is optional; handle accordingly
	}

	var rc revokedCert
	err = json.Unmarshal(p.value, &rc)
	if err != nil {
		fmt.Println("error:", err)
	}

	c, err := base64.RawURLEncoding.DecodeString(rc.Certificate)
	if err != nil {
		fmt.Println("error:", err)
	}

	certToBeRevoked, err := x509.ParseCertificate(c)
	if err != nil {
		fmt.Println("error: failed to parse certificate: " + err.Error())
	}

	// TODO: check reason code; should be allowed; otherwise send error

	options := &authority.RevokeOptions{
		Serial:      certToBeRevoked.SerialNumber.String(),
		Reason:      "test", // TODO: map it to the reason based on code?
		ReasonCode:  rc.Reason,
		PassiveOnly: false,
		MTLS:        true, // TODO: should be false, I guess, but results in error:  authority.Revoke; error parsing token: square/go-jose: compact JWS format must have three parts (OTT)
		Crt:         certToBeRevoked,
		OTT:         "",
	}
	err = h.ca.Revoke(ctx, options)
	if err != nil {
		fmt.Println("error: ", err.Error()) // TODO: send the right error; 400; alreadyRevoked (or something else went wrong, of course)
	}

	w.Write(nil)
}
