package main

import (
	"context"
	"fmt"
	"io"
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

	client, err := ca.BootstrapClient(ctx, token, ca.AddFederationToRootCAs())
	if err != nil {
		panic(err)
	}

	for {
		resp, err := client.Get("https://127.0.0.1:8443")
		if err != nil {
			panic(err)
		}
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			panic(err)
		}

		fmt.Printf("Server responded: %s\n", b)
		time.Sleep(5 * time.Second)
	}
}
