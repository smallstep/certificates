package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/smallstep/certificates/autocert/examples/hello-mtls/go-grpc/hello"
)

const (
	autocertFile     = "/var/run/autocert.step.sm/site.crt"
	autocertKey      = "/var/run/autocert.step.sm/site.key"
	autocertRoot     = "/var/run/autocert.step.sm/root.crt"
	requestFrequency = 5 * time.Second
	tickFrequency    = 15 * time.Second
)

// Uses techniques from https://diogomonica.com/2017/01/11/hitless-tls-certificate-rotation-in-go/
// to automatically rotate certificates when they're renewed.

type rotator struct {
	sync.RWMutex
	certificate *tls.Certificate
}

func (r *rotator) getClientCertificate(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	r.RLock()
	defer r.RUnlock()
	return r.certificate, nil
}

func (r *rotator) loadCertificate(certFile, keyFile string) error {
	r.Lock()
	defer r.Unlock()

	c, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}

	r.certificate = &c

	return nil
}

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

func sayHello(c hello.GreeterClient) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	r, err := c.SayHello(ctx, &hello.HelloRequest{Name: "world"})
	if err != nil {
		return err
	}
	log.Printf("Greeting: %s", r.Message)
	return nil
}

func sayHelloAgain(c hello.GreeterClient) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	r, err := c.SayHelloAgain(ctx, &hello.HelloRequest{Name: "world"})
	if err != nil {
		return err
	}
	log.Printf("Greeting: %s", r.Message)
	return nil
}

func main() {
	// Read the root certificate for our CA from disk
	roots, err := loadRootCertPool()
	if err != nil {
		log.Fatal(err)
	}

	// Load certificate
	r := &rotator{}
	if err := r.loadCertificate(autocertFile, autocertKey); err != nil {
		log.Fatal("error loading certificate and key", err)
	}
	tlsConfig := &tls.Config{
		RootCAs:          roots,
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		// GetClientCertificate is called when a server requests a
		// certificate from a client.
		//
		// In this example keep alives will cause the certificate to
		// only be called once, but if we disable them,
		// GetClientCertificate will be called on every request.
		GetClientCertificate: r.getClientCertificate,
	}

	// Schedule periodic re-load of certificate
	// A real implementation can use something like
	// https://github.com/fsnotify/fsnotify
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(tickFrequency)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				fmt.Println("Checking for new certificate...")
				err := r.loadCertificate(autocertFile, autocertKey)
				if err != nil {
					log.Println("Error loading certificate and key", err)
				}
			case <-done:
				return
			}
		}
	}()
	defer close(done)

	// Set up a connection to the server.
	address := os.Getenv("HELLO_MTLS_URL")
	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	client := hello.NewGreeterClient(conn)

	for {
		if err := sayHello(client); err != nil {
			log.Fatalf("could not greet: %v", err)
		}
		if err := sayHelloAgain(client); err != nil {
			log.Fatalf("could not greet: %v", err)
		}
		time.Sleep(requestFrequency)
	}
}
