package server

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// ServerShutdownTimeout is the default time to wait before closing
// connections on shutdown.
const ServerShutdownTimeout = 60 * time.Second

// Server is a incomplete component that implements a basic HTTP/HTTPS
// server.
type Server struct {
	*http.Server
	listener   *net.TCPListener
	reloadCh   chan net.Listener
	shutdownCh chan struct{}
}

// New creates a new HTTP/HTTPS server configured with the passed
// address, http.Handler and tls.Config.
func New(addr string, handler http.Handler, tlsConfig *tls.Config) *Server {
	return &Server{
		reloadCh:   make(chan net.Listener),
		shutdownCh: make(chan struct{}),
		Server:     newHTTPServer(addr, handler, tlsConfig),
	}
}

// newHTTPServer creates a new http.Server with the TCP address, handler and
// tls.Config.
func newHTTPServer(addr string, handler http.Handler, tlsConfig *tls.Config) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		TLSConfig:         tlsConfig,
		WriteTimeout:      15 * time.Second,
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       15 * time.Second,
		ErrorLog:          log.New(os.Stderr, "", log.Ldate|log.Ltime|log.Llongfile),
	}
}

// ListenAndServe listens on the TCP network address srv.Addr and then calls
// Serve to handle requests on incoming connections.
func (srv *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}

	return srv.Serve(ln)
}

// Serve runs Serve or ServeTLS on the underlying http.Server and listen to
// channels to reload or shutdown the server.
func (srv *Server) Serve(ln net.Listener) error {
	var (
		listener = ln
		err      error
	)

	// Attempt to unwrap the listener if it's a [Listener].
	wl, isWrapped := listener.(*Listener)
	if isWrapped {
		listener = wl.listener.Unwrap()
	}

	// Store the current listener. When the server is reloaded a copy of the
	// underlying os.File is created, so when the server is closed, it does
	// not affect the copy.
	if ll, ok := listener.(*net.TCPListener); ok {
		srv.listener = ll
	}

	for {
		switch {
		case srv.TLSConfig == nil || (len(srv.TLSConfig.Certificates) == 0 && srv.TLSConfig.GetCertificate == nil):
			log.Printf("Serving HTTP on %s ...", srv.Addr)
			err = srv.Server.Serve(ln)
		case isWrapped:
			log.Printf("Serving %s on %s ...", wl.proto, wl.Addr())
			err = srv.Server.Serve(wl)
		default:
			log.Printf("Serving HTTPS on %s ...", srv.Addr)
			err = srv.Server.ServeTLS(ln, "", "")
		}

		// log unexpected errors
		if err != http.ErrServerClosed {
			log.Println(errors.Wrap(err, "unexpected error"))
		}

		select {
		case ln = <-srv.reloadCh:
			srv.listener = ln.(*net.TCPListener)
		case <-srv.shutdownCh:
			return http.ErrServerClosed
		}
	}
}

// UnwrappableListener indicates a [net.Listener] that can
// be unwrapped to obtain the underlying [net.Listener]. It
// is used by the [Server] to obtain a [*net.TCPListener]
// implementing the [net.Listener] interface.
type UnwrappableListener interface {
	net.Listener
	Unwrap() net.Listener
}

// NewListener wraps the inner [net.Listener].
func NewListener(listener UnwrappableListener, proto string) *Listener {
	return &Listener{
		listener: listener,
		proto:    strings.ToUpper(proto),
	}
}

// Listener wraps a [net.Listener].
type Listener struct {
	listener UnwrappableListener
	proto    string
}

// Accept waits for and returns the next connection to the listener.
func (w *Listener) Accept() (net.Conn, error) {
	return w.listener.Accept()
}

// Close closes the listener.
// Any blocked Accept operations will be unblocked and return errors.
func (w *Listener) Close() error {
	return w.listener.Close()
}

// Addr returns the listener's network address.
func (w *Listener) Addr() net.Addr {
	return w.listener.Addr()
}

// Shutdown gracefully shuts down the server without interrupting any active
// connections.
func (srv *Server) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), ServerShutdownTimeout)
	defer cancel()              // release resources if Shutdown ends before the timeout
	defer close(srv.shutdownCh) // close shutdown channel
	return srv.Server.Shutdown(ctx)
}

func (srv *Server) reloadShutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), ServerShutdownTimeout)
	defer cancel() // release resources if Shutdown ends before the timeout
	return srv.Server.Shutdown(ctx)
}

// Reload reloads the current server with the configuration of the passed
// server.
func (srv *Server) Reload(ns *Server) error {
	var err error
	var ln net.Listener

	if srv.Addr != ns.Addr {
		// Open new address
		ln, err = net.Listen("tcp", ns.Addr)
		if err != nil {
			return errors.WithStack(err)
		}
	} else {
		// Get a copy of the underlying os.File
		fd, err := srv.listener.File()
		if err != nil {
			return errors.WithStack(err)
		}
		// Make sure to close the copy
		defer fd.Close()

		// Creates a new listener copying fd
		ln, err = net.FileListener(fd)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	// Close old server without sending a signal
	if err := srv.reloadShutdown(); err != nil {
		return err
	}

	// Update old server
	srv.Server = ns.Server
	srv.reloadCh <- ln
	return nil
}

// Forbidden writes on the http.ResponseWriter a text/plain forbidden
// response.
func (srv *Server) Forbidden(w http.ResponseWriter) {
	header := w.Header()
	header.Set("Content-Type", "text/plain; charset=utf-8")
	header.Set("Content-Length", "11")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte("Forbidden.\n"))
}
