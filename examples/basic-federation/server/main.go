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
			issuer := "none"
			if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
				name = r.TLS.PeerCertificates[0].Subject.CommonName
				issuer = r.TLS.PeerCertificates[len(r.TLS.PeerCertificates)-1].Issuer.CommonName
			}

			w.Write([]byte(fmt.Sprintf("Hello %s (cert issued by '%s') at %s", name, issuer, time.Now().UTC())))
		}),
	}, ca.AddFederationToClientCAs(), ListTrustedRoots())
	if err != nil {
		panic(err)
	}

	fmt.Println("Listening on :8443 ...")
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		panic(err)
	}
}

// ListTrustedRoots prints list of trusted roots for illustration purposes
func ListTrustedRoots() ca.TLSOption {
	fn := func(ctx *ca.TLSOptionCtx) error {
		certs, err := ctx.Client.Federation()
		if err != nil {
			return err
		}
		roots, err := ctx.Client.Roots()
		if err != nil {
			return err
		}

		if len(certs.Certificates) > len(roots.Certificates) {
			fmt.Println("Server is using federated root certificates")
		}
		for _, cert := range certs.Certificates {
			fmt.Printf("Accepting certs anchored in %s\n", cert.Certificate.Subject)
		}

		return nil
	}
	return func(ctx *ca.TLSOptionCtx) error {
		ctx.OnRenewFunc = append(ctx.OnRenewFunc, fn)
		return fn(ctx)
	}
}
