package api

import (
	"encoding/pem"
	"net/http"

	"github.com/smallstep/certificates/api/render"
)

// CRL is an HTTP handler that returns the current CRL in DER or PEM format
func CRL(w http.ResponseWriter, r *http.Request) {
	crlBytes, err := mustAuthority(r.Context()).GetCertificateRevocationList()
	if err != nil {
		render.Error(w, err)
		return
	}

	_, formatAsPEM := r.URL.Query()["pem"]
	if formatAsPEM {
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "X509 CRL",
			Bytes: crlBytes,
		})
		w.Header().Add("Content-Type", "application/x-pem-file")
		w.Header().Add("Content-Disposition", "attachment; filename=\"crl.pem\"")
		w.Write(pemBytes)
	} else {
		w.Header().Add("Content-Type", "application/pkix-crl")
		w.Header().Add("Content-Disposition", "attachment; filename=\"crl.der\"")
		w.Write(crlBytes)
	}
}
