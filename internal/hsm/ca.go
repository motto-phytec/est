/*
Copyright (c) 2021 PHYTEC Messtechnik GmbH

Licensed under the MIT License (the "License"); you may not use this file except
in compliance with the License. You may obtain a copy of the License at

https://opensource.org/licenses/MIT

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package hsmca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"time"

	"go.mozilla.org/pkcs7"

	"github.com/ThalesIgnite/crypto11"
	"github.com/globalsign/pemfile"

	"github.com/motto-phytec/est"
)

// HSMCA
type HSMCA struct {
	certs  []*x509.Certificate
	tmpl   *x509.Certificate
	signer *crypto.Signer
}

// Global constants.
const (
	alphanumerics              = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	bitSizeHeader              = "Bit-Size"
	csrAttrsAPS                = "csrattrs"
	defaultCertificateDuration = time.Hour * 24 * 90
	serverKeyGenPassword       = "pseudohistorical"
	rootCertificateDuration    = time.Hour * 24
	triggerErrorsAPS           = "triggererrors"
)

// Global variables.
var (
	oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
)

func init() {
	// Set default content encryption algorithm for PKCS7 package, which
	// otherwise defaults to 3DES.
	pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES128GCM
}

// CACerts returns the CA certificates, unless the additional path segment is
// "triggererrors", in which case an error is returned for testing purposes.
func (ca *HSMCA) CACerts(
	ctx context.Context,
	aps string,
	r *http.Request,
) ([]*x509.Certificate, error) {
	if aps == triggerErrorsAPS {
		return nil, errors.New("triggered error")
	}

	return ca.certs, nil
}

// CSRAttrs returns an empty sequence of CSR attributes, unless the additional
// path segment is:
//  - "csrattrs", in which case it returns the same example sequence described
//    in RFC7030 4.5.2; or
//  - "triggererrors", in which case an error is returned for testing purposes.
func (ca *HSMCA) CSRAttrs(
	ctx context.Context,
	aps string,
	r *http.Request,
) (attrs est.CSRAttrs, err error) {
	switch aps {
	case csrAttrsAPS:
		attrs = est.CSRAttrs{
			OIDs: []asn1.ObjectIdentifier{
				{1, 2, 840, 113549, 1, 9, 7},
				{1, 2, 840, 10045, 4, 3, 3},
			},
			Attributes: []est.Attribute{
				{
					Type:   asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14},
					Values: est.AttributeValueSET{asn1.ObjectIdentifier{1, 3, 6, 1, 1, 1, 1, 22}},
				},
				{
					Type:   asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1},
					Values: est.AttributeValueSET{asn1.ObjectIdentifier{1, 3, 132, 0, 34}},
				},
			},
		}

	case triggerErrorsAPS:
		err = errors.New("triggered error")
	}

	return attrs, err
}

// Enroll issues a new certificate with:
//   - a 90 day duration from the current time
//   - a randomly generated 128-bit serial number
//   - a subject and subject alternative name copied from the provided CSR
//   - a default set of key usages and extended key usages
//   - a basic constraints extension with cA flag set to FALSE
//
// unless the additional path segment is "triggererrors", in which case the
// following errors will be returned for testing purposes, depending on the
// common name in the CSR:
//
//   - "Trigger Error Forbidden", HTTP status 403
//   - "Trigger Error Deferred", HTTP status 202 with retry of 600 seconds
//   - "Trigger Error Unknown", untyped error expected to be interpreted as
//     an internal server error.
func (ca *HSMCA) Enroll(
	ctx context.Context,
	csr *x509.CertificateRequest,
	aps string,
	r *http.Request,
) (*x509.Certificate, error) {
	// Process any requested triggered errors.
	if aps == triggerErrorsAPS {
		switch csr.Subject.CommonName {
		case "Trigger Error Forbidden":
			return nil, caError{
				status: http.StatusForbidden,
				desc:   "triggered forbidden response",
			}

		case "Trigger Error Deferred":
			return nil, caError{
				status:     http.StatusAccepted,
				desc:       "triggered deferred response",
				retryAfter: 600,
			}

		case "Trigger Error Unknown":
			return nil, errors.New("triggered error")
		}
	}

	// Generate certificate template, copying the raw subject and raw
	// SubjectAltName extension from the CSR.
	sn, err := rand.Int(rand.Reader, big.NewInt(1).Exp(big.NewInt(2), big.NewInt(128), nil))
	if err != nil {
		return nil, fmt.Errorf("failed to make serial number: %w", err)
	}

	ski, err := makePublicKeyIdentifier(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to make public key identifier: %w", err)
	}

	now := time.Now()
	notAfter := now.Add(defaultCertificateDuration)
	if latest := ca.certs[0].NotAfter.Sub(notAfter); latest < 0 {
		// Don't issue any certificates which expire after the CA certificate.
		notAfter = ca.certs[0].NotAfter
	}

	var tmpl = &x509.Certificate{
		SerialNumber:          sn,
		NotBefore:             now,
		NotAfter:              notAfter,
		RawSubject:            csr.RawSubject,
		SubjectKeyId:          ski,
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	for _, ext := range csr.Extensions {
		if ext.Id.Equal(oidSubjectAltName) {
			tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
			break
		}
	}

	// Create and return certificate.
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.certs[0], csr.PublicKey, ca.signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// Reenroll implements est.CA but simply passes the request through to Enroll.
func (ca *HSMCA) Reenroll(
	ctx context.Context,
	cert *x509.Certificate,
	csr *x509.CertificateRequest,
	aps string,
	r *http.Request,
) (*x509.Certificate, error) {
	return ca.Enroll(ctx, csr, aps, r)
}

// ServerKeyGen creates a new RSA private key and then calls Enroll. It returns
// the key in PKCS8 DER-encoding, unless the additional path segment is set to
// "pkcs7", in which case it is returned wrapped in a CMS SignedData structure
// signed by the CA certificate(s), itself wrapped in a CMS EnvelopedData
// encrypted with the pre-shared key "pseudohistorical". A "Bit-Size" HTTP
// header may be passed with the values 2048, 3072 or 4096.
func (ca *HSMCA) ServerKeyGen(
	ctx context.Context,
	csr *x509.CertificateRequest,
	aps string,
	r *http.Request,
) (*x509.Certificate, []byte, error) {
	fmt.Errorf("Server Key Generation with HSM is not supported")
	return nil, nil, nil
}

// TPMEnroll requests a new certificate using the TPM 2.0 privacy-preserving
// protocol. An EK certificate chain with a length of at least one must be
// provided, along with the EK and AK public areas. The return values are an
// encrypted credential, a wrapped encryption key, and the certificate itself
// encrypted with the encrypted credential in AES 128 Galois Counter Mode
// inside a CMS EnvelopedData structure.
func (ca *HSMCA) TPMEnroll(
	ctx context.Context,
	csr *x509.CertificateRequest,
	ekcerts []*x509.Certificate,
	ekPub, akPub []byte,
	aps string,
	r *http.Request,
) ([]byte, []byte, []byte, error) {
	return nil, nil, nil, fmt.Errorf("tpm enroll with HSM is not supported")
}

// New creates a new mock certificate authority. If more than one CA certificate
// is provided, they should be in order with the issuing (intermediate) CA
// certificate first, and the root CA certificate last. The private key should
// be associated with the public key in the first, issuing CA certificate.
func New(cacerts []*x509.Certificate, templ *x509.Certificate, signer *crypto.Signer) (*HSMCA, error) {
	if len(cacerts) < 1 {
		return nil, errors.New("no CA certificates provided")
	} else if signer == nil {
		return nil, errors.New("no signer provided")
	}

	for i := range cacerts {
		if !cacerts[i].IsCA {
			return nil, fmt.Errorf("certificate at index %d is not a CA certificate", i)
		}
	}

	return &HSMCA{
		certs:  cacerts,
		tmpl:   templ,
		signer: signer,
	}, nil
}

// NewFromFiles creates a new mock certificate authority from a PEM-encoded
// CA certificates chain and a (unencrypted) PEM-encoded private key contained
// in files. If more than one certificate is contained in the file, the
// certificates should appear in order with the issuing (intermediate) CA
// certificate first, and the root certificate last. The private key should be
// associated with the public key in the first certificate in certspath.
func NewFromHSM(certinter, keypath, templpath string, configpath string) (*HSMCA, error) {
	var ctx *crypto11.Context
	var err error
	var templ *x509.Certificate = createCAtemplate(templpath)
	if templ == nil {
		return nil, fmt.Errorf("unknown CA template : %s", templpath)
	}
	if configpath == "" {
		return nil, fmt.Errorf("must be start with configuration file")
	}
	var certs []*x509.Certificate
	if _, err := os.Stat(certinter); err == nil {
		certs, err = pemfile.ReadCerts(certinter)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA certificates from file: %w", err)
		}
	} else {
		// load from HSM
		ctx, err = crypto11.ConfigureFromFile(configpath)
		if err != nil {
			return nil, fmt.Errorf("failed to load crypto11 configfile from file: %w", err)
		}
		certs[0], err = ctx.FindCertificate(nil, []byte(certinter), nil)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA certificates from HSM: %w", err)
		}
	}

	if _, err := os.Stat(keypath); err == nil {
		return nil, fmt.Errorf("Error: Private Key as file is not allowed")
	}

	if _, err := os.Stat(keypath); err == nil {
		return nil, fmt.Errorf("CA private key must stored in hsm: %w", err)
	}

	ctx, err = crypto11.ConfigureFromFile(configpath)
	if err != nil {
		return nil, fmt.Errorf("failed to load crypto11 configfile from file: %w", err)
	}

	var signer crypto.Signer
	if signer, err = ctx.FindKeyPair(nil, []byte(keypath)); err != nil {
		return nil, fmt.Errorf("failed to load crypto11 key from hsm: %w", err)
	}

	return New(certs, templ, signer)
}

// makePublicKeyIdentifier builds a public key identifier in accordance with the
// first method described in RFC5280 section 4.2.1.2.
func makePublicKeyIdentifier(pub crypto.PublicKey) ([]byte, error) {
	keyBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	id := sha1.Sum(keyBytes)

	return id[:], nil
}
