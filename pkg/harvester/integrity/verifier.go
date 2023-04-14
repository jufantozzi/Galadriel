package integrity

import (
	"crypto/x509"
)

// Verifier is the certificate material provider for signing and validation operations.
type Verifier interface {
	GetSigningCertificate() (*x509.Certificate, error)
	GetValidationCertificate() ([]*x509.Certificate, error)
}

// diskReader provides a disk implementation of Verifier
type diskReader struct {
	scPath string
	vcPath string
}

func NewLocalReader(signingCertificatePath, validationCertificatePath string) (Verifier, error) {
	return &diskReader{
		scPath: signingCertificatePath,
		vcPath: validationCertificatePath,
	}, nil
}

func (d *diskReader) GetSigningCertificate() (*x509.Certificate, error) {
	return nil, nil
}

func (d *diskReader) GetValidationCertificate() ([]*x509.Certificate, error) {
	return nil, nil
}
