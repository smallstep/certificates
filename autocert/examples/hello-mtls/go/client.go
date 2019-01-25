package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	autocertFile     = "/var/run/autocert.step.sm/site.crt"
	autocertKey      = "/var/run/autocert.step.sm/site.key"
	autocertRoot     = "/var/run/autocert.step.sm/root.crt"
	requestFrequency = 5 * time.Second
)

func loadRootCertPool() (*x509.CertPool, error) {
	root, err := ioutil.ReadFile(autocertRoot)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(root); !ok {
		return nil, errors.New("Missing or invalid root certificate")
	}

	return pool, nil
}

func main() {
	url := os.Getenv("HELLO_MTLS_URL")

	// Read our leaf certificate and key from disk
	cert, err := tls.LoadX509KeyPair(autocertFile, autocertKey)
	if err != nil {
		log.Fatal(err)
	}

	// Read the root certificate for our CA from disk
	roots, err := loadRootCertPool()
	if err != nil {
		log.Fatal(err)
	}

	// Create an HTTPS client using our cert, key & pool
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:          roots,
				Certificates:     []tls.Certificate{cert},
				MinVersion:       tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				},
			},
		},
	}

	for {
		// Make request
		r, err := client.Get(url)
		if err != nil {
			log.Fatal(err)
		}

		defer r.Body.Close()
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%s: %s\n", time.Now().Format(time.RFC3339), strings.Trim(string(body), "\n"))

		time.Sleep(requestFrequency)
	}
}
