package hsmca

import (
	"crypto/x509"
	"time"
)

var cDefZeroTime = time.Date(0, time.January, 1, 0, 0, 0, 0, time.UTC)

type catmplstruct struct {
	tmpl         *x509.Certificate
	certduration time.Duration
}

func createCAtemplate(tmpl string) *catmplstruct {
	var certstruct *catmplstruct
	certstruct.tmpl = nil

	switch tmpl {
	case "ksp0563_v1":
		certstruct.tmpl = &x509.Certificate{
			NotBefore:             cDefZeroTime,
			NotAfter:              time.Date(2100, time.January, 1, 1, 11, 11, 11, &time.Location{}),
			BasicConstraintsValid: true,
			IsCA:                  false,
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		certstruct.certduration = time.Duration(time.Now().Year() + 100)
	}
	return certstruct
}
