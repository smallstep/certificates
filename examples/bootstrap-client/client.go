package main

import (
	"fmt"
	"io/ioutil"
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

	client, err := ca.BootstrapClient(token)
	if err != nil {
		panic(err)
	}

	for {
		resp, err := client.Get("https://localhost:8443")
		if err != nil {
			panic(err)
		}
		b, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			panic(err)
		}

		fmt.Printf("Server responded: %s\n", b)
		time.Sleep(1 * time.Second)
	}
}
