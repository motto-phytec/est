package hsmca

import (
	"crypto/x509"
	"time"
)

func createCAtemplate(tmpl string) *x509.Certificate {
	var cert *x509.Certificate = nil

	switch tmpl {
	case "ksp0563_v1":
		cert = &x509.Certificate{
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(time.Hour * 24 * 365 * 10),
			BasicConstraintsValid: true,
			IsCA:                  false,
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		}
	default:
		cert = nil
	}

	return cert
}
