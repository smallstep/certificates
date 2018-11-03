package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/smallstep/certificates/ca"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <token>\n", os.Args[0])
		os.Exit(1)
	}

	token := os.Args[1]

	srv, err := ca.BootstrapServer(":8443", token, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := "nobody"
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			name = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		w.Write([]byte(fmt.Sprintf("Hello %s at %s!!!", name, time.Now().UTC())))
	}))
	if err != nil {
		panic(err)
	}

	fmt.Println("Listening on :8443 ...")
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		panic(err)
	}
}
