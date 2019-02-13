package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/smallstep/certificates/autocert/examples/hello-mtls/go-grpc/hello"
)

const (
	autocertFile  = "/var/run/autocert.step.sm/site.crt"
	autocertKey   = "/var/run/autocert.step.sm/site.key"
	autocertRoot  = "/var/run/autocert.step.sm/root.crt"
	tickFrequency = 15 * time.Second
)

// Uses techniques from https://diogomonica.com/2017/01/11/hitless-tls-certificate-rotation-in-go/
// to automatically rotate certificates when they're renewed.

type rotator struct {
	sync.RWMutex
	certificate *tls.Certificate
}

func (r *rotator) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
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

// Greeter is a service that sends greetings.
type Greeter struct{}

// SayHello sends a greeting
func (g *Greeter) SayHello(ctx context.Context, in *hello.HelloRequest) (*hello.HelloReply, error) {
	return &hello.HelloReply{Message: "Hello " + in.Name + " (" + getServerName(ctx) + ")"}, nil
}

// SayHelloAgain sends another greeting
func (g *Greeter) SayHelloAgain(ctx context.Context, in *hello.HelloRequest) (*hello.HelloReply, error) {
	return &hello.HelloReply{Message: "Hello again " + in.Name + " (" + getServerName(ctx) + ")"}, nil
}

func getServerName(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok {
		if tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo); ok {
			return tlsInfo.State.ServerName
		}
	}
	return "unknown"
}

func main() {
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
		ClientAuth:               tls.RequireAndVerifyClientCert,
		ClientCAs:                roots,
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		GetCertificate: r.getCertificate,
	}

	// Schedule periodic re-load of certificate
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

	lis, err := net.Listen("tcp", ":443")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	hello.RegisterGreeterServer(srv, &Greeter{})

	log.Println("Listening on :443")
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
