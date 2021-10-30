package api

import "net/http"

// CRL is an HTTP handler that returns the current CRL
func (h *caHandler) CRL(w http.ResponseWriter, r *http.Request) {
	crl, err := h.Authority.GenerateCertificateRevocationList(false)

	if err != nil {
		w.WriteHeader(500)
		return
	}

	w.WriteHeader(200)
	_, err = w.Write([]byte(crl))
}
