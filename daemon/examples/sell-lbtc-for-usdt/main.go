package main

import (
	"log"
	"os"

	"github.com/aejkcs50/seqdex/daemon/examples"
)

const (
	daemonAddr   = "localhost:9945"
	explorerAddr = "http://localhost:3001"
)

func main() {
	if err := examples.SellExample(daemonAddr, explorerAddr); err != nil {
		log.Fatal(err)
	}
	os.Exit(0)
}
