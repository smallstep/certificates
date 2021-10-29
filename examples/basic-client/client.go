package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/smallstep/certificates/ca"
)

func printResponse(name string, v interface{}) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s response:\n%s\n\n", name, b)
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <token>\n", os.Args[0])
		os.Exit(1)
	}

	token := os.Args[1]

	// To create the client using ca.NewClient we need:
	// * The CA address "https://localhost:9000"
	// * The root certificate fingerprint
	// 84a033e84196f73bd593fad7a63e509e57fd982f02084359c4e8c5c864efc27d to get
	// the root fingerprint we can use `step certificate fingerprint root_ca.crt`
	client, err := ca.NewClient("https://localhost:9000", ca.WithRootSHA256("84a033e84196f73bd593fad7a63e509e57fd982f02084359c4e8c5c864efc27d"))
	if err != nil {
		panic(err)
	}

	// Other ways to initialize the client would be:
	// * With the Bootstrap functionality (recommended):
	//   client, err := ca.Bootstrap(token)
	// * Using the root certificate instead of the fingerprint:
	//   client, err := ca.NewClient("https://localhost:9000", ca.WithRootFile("../pki/secrets/root_ca.crt"))

	// Get the health of the CA
	health, err := client.Health()
	if err != nil {
		panic(err)
	}
	printResponse("Health", health)

	// Get and verify a root CA
	root, err := client.Root("84a033e84196f73bd593fad7a63e509e57fd982f02084359c4e8c5c864efc27d")
	if err != nil {
		panic(err)
	}
	printResponse("Root", root)

	// We can use ca.CreateSignRequest to generate a new sign request with a
	// randomly generated key.
	req, pk, err := ca.CreateSignRequest(token)
	if err != nil {
		panic(err)
	}
	sign, err := client.Sign(req)
	if err != nil {
		panic(err)
	}
	printResponse("Sign", sign)

	// Renew a certificate with a transport that contains the previous
	// certificate. We should created a context that allows us to finish the
	// renewal goroutine.∑
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // Finish the renewal goroutine
	tr, err := client.Transport(ctx, sign, pk)
	if err != nil {
		panic(err)
	}
	renew, err := client.Renew(tr)
	if err != nil {
		panic(err)
	}
	printResponse("Renew", renew)

	// Get tls.Config for a server
	ctxServer, cancelServer := context.WithCancel(context.Background())
	defer cancelServer()
	tlsConfig, err := client.GetServerTLSConfig(ctxServer, sign, pk)
	if err != nil {
		panic(err)
	}
	// An http server will use the tls.Config like:
	_ = &http.Server{
		Addr: ":443",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Hello world"))
		}),
		TLSConfig: tlsConfig,
	}

	// Get tls.Config for a client
	ctxClient, cancelClient := context.WithCancel(context.Background())
	defer cancelClient()
	tlsConfig, err = client.GetClientTLSConfig(ctxClient, sign, pk)
	if err != nil {
		panic(err)
	}
	// An http.Client will need to create a transport first
	_ = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
			// Options set in http.DefaultTransport
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	// But we can just use client.Transport to get the default configuration
	ctxTransport, cancelTransport := context.WithCancel(context.Background())
	defer cancelTransport()
	tr, err = client.Transport(ctxTransport, sign, pk)
	if err != nil {
		panic(err)
	}
	// And http.Client will use the transport like
	_ = &http.Client{
		Transport: tr,
	}

	// Get provisioners and provisioner keys. In this example we add two
	// optional arguments with the initial cursor and a limit.
	//
	// A server or a client should not need this functionality, they are used to
	// sign (private key) and verify (public key) tokens. The step cli can be
	// used for this purpose.
	provisioners, err := client.Provisioners(ca.WithProvisionerCursor(""), ca.WithProvisionerLimit(100))
	if err != nil {
		panic(err)
	}
	printResponse("Provisioners", provisioners)
	// Get encrypted key
	key, err := client.ProvisionerKey("DmAtZt2EhmZr_iTJJ387fr4Md2NbzMXGdXQNW1UWPXk")
	if err != nil {
		panic(err)
	}
	printResponse("Provisioner Key", key)
}
