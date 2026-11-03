package api

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smallstep/pkcs7"
	smallscep "github.com/smallstep/scep"
	"go.step.sm/crypto/minica"

	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/scep"
)

// oidSCEPfailInfoText mirrors the attribute the CA signs into failure CertReps.
var oidSCEPfailInfoText = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 24, 1}

type noopSignAuthority struct{}

func (noopSignAuthority) SignWithContext(_ context.Context, _ *x509.CertificateRequest, _ provisioner.SignOptions, _ ...provisioner.SignOption) ([]*x509.Certificate, error) {
	return nil, errors.New("not implemented")
}

func (noopSignAuthority) LoadProvisionerByName(string) (provisioner.Interface, error) {
	return &provisioner.SCEP{}, nil
}

// TestCreateFailureResponseWireUnchanged proves the client-visible CertRep is
// unchanged when the real error is passed as failError: the signed attributes
// carry the same failInfo and infoText as before, and the internal failError
// text never appears in the DER bytes.
func TestCreateFailureResponseWireUnchanged(t *testing.T) {
	ca, err := minica.New(minica.WithGetSignerFunc(func() (crypto.Signer, error) {
		return rsa.GenerateKey(rand.Reader, 2048)
	}))
	require.NoError(t, err)

	auth, err := scep.New(noopSignAuthority{}, scep.Options{
		Roots:         []*x509.Certificate{ca.Root},
		Intermediates: []*x509.Certificate{ca.Intermediate},
		SignerCert:    ca.Intermediate,
		Signer:        ca.Signer,
	})
	require.NoError(t, err)

	ctx := scep.NewProvisionerContext(scep.NewContext(context.Background(), auth), &provisioner.SCEP{})
	msg := &scep.PKIMessage{
		TransactionID: smallscep.TransactionID("txn-123"),
		MessageType:   smallscep.PKCSReq,
		SenderNonce:   smallscep.SenderNonce("0123456789abcdef"),
	}

	webhookErr := &url.Error{Op: "Post", URL: "https://hooks.example.com/validate?token=secret", Err: errors.New("connection refused")}

	cases := []struct {
		name      string
		infoText  string
		failError error
		// skipByteCheck when failError text is also the infoText (already on the wire).
		skipByteCheck bool
	}{
		{"challenge invalid", "webhook server did not allow request", errors.New("webhook server did not allow request"), true},
		{"challenge validation error", "failed validating challenge password", webhookErr, false},
		{"unexpected message type", "unexpected message type: (19)", fmt.Errorf("unexpected message type: (%s)", smallscep.PKCSReq), false},
		{"signing failure", "internal server error; please see the certificate authority logs for more info", fmt.Errorf("error when signing new certificate: %w", errors.New("boom")), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := createFailureResponse(ctx, nil, msg, smallscep.BadRequest, tc.infoText, tc.failError)
			require.NoError(t, err)

			// The internal error is returned for logging, not for the wire.
			require.ErrorIs(t, resp.Error, tc.failError)

			// The CertRep still parses as a FAILURE with failInfo badRequest.
			parsed, err := smallscep.ParsePKIMessage(resp.Data)
			require.NoError(t, err)
			require.Equal(t, smallscep.FAILURE, parsed.PKIStatus)
			require.Equal(t, smallscep.BadRequest, parsed.FailInfo)

			// The signed failInfoText attribute is the fixed client-facing sentence.
			p7, err := pkcs7.Parse(resp.Data)
			require.NoError(t, err)
			var text string
			require.NoError(t, p7.UnmarshalSignedAttribute(oidSCEPfailInfoText, &text))
			require.Equal(t, tc.infoText, text)

			// The internal failError text is not in the DER bytes.
			if !tc.skipByteCheck {
				require.NotContains(t, string(resp.Data), tc.failError.Error())
				require.False(t, bytes.Contains(resp.Data, []byte("token=secret")))
			}
		})
	}
}
