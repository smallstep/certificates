package api

import (
	"encoding/pem"
	"net/http"
	"time"

	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/errs"
)

// CRL is an HTTP handler that returns the current CRL in DER or PEM format
func CRL(w http.ResponseWriter, r *http.Request) {
	crlInfo, err := mustAuthority(r.Context()).GetCertificateRevocationList()
	if err != nil {
		render.Error(w, r, err)
		return
	}

	if crlInfo == nil {
		render.Error(w, r, errs.New(http.StatusNotFound, "no CRL available"))
		return
	}

	expires := crlInfo.ExpiresAt
	if expires.IsZero() {
		expires = time.Now()
	}

	w.Header().Add("Expires", expires.Format(time.RFC1123))

	_, formatAsPEM := r.URL.Query()["pem"]
	if formatAsPEM {
		w.Header().Add("Content-Type", "application/x-pem-file")
		w.Header().Add("Content-Disposition", "attachment; filename=\"crl.pem\"")

		_ = pem.Encode(w, &pem.Block{
			Type:  "X509 CRL",
			Bytes: crlInfo.Data,
		})
	} else {
		w.Header().Add("Content-Type", "application/pkix-crl")
		w.Header().Add("Content-Disposition", "attachment; filename=\"crl.der\"")
		w.Write(crlInfo.Data)
	}
}
