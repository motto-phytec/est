package main

import (
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/globalsign/pemfile"
)

func main() {
	log.SetPrefix(fmt.Sprintf("%s: ", "esttemplate"))
	log.SetFlags(0)

	now := time.Now()
	notAfter := time.Now().Add(time.Hour * 24 * 90)

	var tmpl = &x509.Certificate{
		NotBefore:             now,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	out, err := os.OpenFile("/home/template.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		log.Fatalf("failed to create output file: %v", err)
	}
	defer out.Close()

	if err := pemfile.WriteCert(out, tmpl); err != nil {
		log.Fatalf("failed to write CA certificate: %v", err)
	}

}
