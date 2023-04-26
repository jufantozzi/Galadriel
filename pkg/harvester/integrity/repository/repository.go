package repository

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"time"
)

// SignCertProvider provides signing certificates
type SignCertProvider interface {
	//IssueSigningCertificateion generates a signing certificate associated to a key pair that will be used to sign SPIRE trust bundles.
	IssueSigningCertificate(*X509CertificateParams) (*x509.Certificate, error)
}

// ValidationCertProvider provides a validation bundle to verify signing certificates.
type ValidationCertProvider interface {
	RetrieveValidationMaterial() ([]*x509.Certificate, error)
}

// X509CertificateParams holds the parameters for issuing an X509 certificate.
type X509CertificateParams struct {
	// PublicKey to be set in the certificate
	PublicKey crypto.PublicKey
	Subject   pkix.Name
	URIs      []*url.URL
	DNSNames  []string
	TTL       time.Duration
}
