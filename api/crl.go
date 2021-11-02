package api

import (
	"encoding/pem"
	"net/http"
)

// CRL is an HTTP handler that returns the current CRL in PEM format
func (h *caHandler) CRL(w http.ResponseWriter, r *http.Request) {
	crlBytes, err := h.Authority.GenerateCertificateRevocationList(false)

	if err != nil {
		w.WriteHeader(500)
		return
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: crlBytes,
	})

	w.WriteHeader(200)
	_, err = w.Write(pemBytes)
}
