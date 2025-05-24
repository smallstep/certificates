package main

import (
	"context"
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

	// make sure to cancel the renew goroutine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := ca.BootstrapServer(ctx, token, &http.Server{
		Addr: ":8443",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			name := "nobody"
			if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
				name = r.TLS.PeerCertificates[0].Subject.CommonName
			}
			fmt.Fprintf(w, "Hello %s at %s!!!", name, time.Now().UTC())
		}),
		ReadHeaderTimeout: 30 * time.Second,
	})
	if err != nil {
		panic(err)
	}

	fmt.Println("Listening on :8443 ...")
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		panic(err)
	}
}
