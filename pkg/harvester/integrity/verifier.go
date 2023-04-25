package integrity

import (
	"crypto/x509"
)

type Signer interface {
	Sign(payload []byte) (signature []byte, signingCert *x509.Certificate, e error)
}

type Verifier interface {
	Verify(rawBundle, signature []byte, signingCert *x509.Certificate) error
}

type Key struct {
	TrustDomainName string
	Certificate     *x509.Certificate
}

type signer struct{}
type verifier struct{}

func NewSigner(signingCertificatePath string) (Signer, error) {
	return &signer{}, nil
}

func NewVerifier(signingCertificatePath string) (Verifier, error) {
	return &verifier{}, nil
}

func (d *signer) Sign(payload []byte) ([]byte, *x509.Certificate, error) {
	return payload, nil, nil
}

func (d *verifier) Verify(rawBundle, signature []byte, signingCert *x509.Certificate) error {
	return nil
}
