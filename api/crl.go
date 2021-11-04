package api

import (
	"encoding/pem"
	"fmt"
	"github.com/pkg/errors"
	"net/http"
)

// CRL is an HTTP handler that returns the current CRL in DER or PEM format
func (h *caHandler) CRL(w http.ResponseWriter, r *http.Request) {
	crlBytes, err := h.Authority.GetCertificateRevocationList()

	_, formatAsPEM := r.URL.Query()["pem"]

	if err != nil {
		w.WriteHeader(500)
		_, err = fmt.Fprintf(w, "%v\n", err)
		if err != nil {
			panic(errors.Wrap(err, "error writing http response"))
		}
		return
	}

	if crlBytes == nil {
		w.WriteHeader(404)
		_, err = fmt.Fprintln(w, "No CRL available")
		if err != nil {
			panic(errors.Wrap(err, "error writing http response"))
		}
		return
	}

	if formatAsPEM {
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "X509 CRL",
			Bytes: crlBytes,
		})
		w.Header().Add("Content-Type", "application/x-pem-file")
		w.Header().Add("Content-Disposition", "attachment; filename=\"crl.pem\"")
		_, err = w.Write(pemBytes)
	} else {
		w.Header().Add("Content-Type", "application/pkix-crl")
		w.Header().Add("Content-Disposition", "attachment; filename=\"crl.der\"")
		_, err = w.Write(crlBytes)
	}

	w.WriteHeader(200)

	if err != nil {
		panic(errors.Wrap(err, "error writing http response"))
	}

}
