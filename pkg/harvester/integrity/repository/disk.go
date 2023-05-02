package repository

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/url"
	"time"

	"github.com/andres-erbsen/clock"
)

// disk is a SigningCA that generates signing certificates and validation materials and has access to root keys and root certs via a path.
type disk struct {
	//rootSigner is the root Key of the signing CA
	rootSigner crypto.Signer
	//rootCertificate is the  root certificate of the signing CA
	rootCertificate *x509.Certificate
	//validationBundle is the list of certificates to be used for validation of signing certificates
	validationBundle []*x509.Certificate
}

type Config struct {
	//CerFilePath is the path to the root CA certificate
	CertFilePath string `hcl:"cert_file_path"`
	//KeyPath is the path to the Root Key
	KeyPath string `hcl:"key_file_path"`
	//ValidationMaterialPath is the path to the TrustBundle to validate CA signed material
	ValidationMaterialPath string `hcl:"validation_material_path"`
}

// New cretes a new disk that is not configured.
func New() (*disk, error) {
	return &disk{}, nil
}

// Configure sets the values of the Disk structure based on an hcl map.
func (dc *disk) Configure(config *Config) error {

	if config.KeyPath == "" {
		return errors.New("key path is not set")
	}

	if config.CertFilePath == "" {
		return errors.New("cert path is not set")
	}

	key, err := getRootKey(config.KeyPath)
	if err != nil {
		return err
	}

	cert, err := getRootCert(config.CertFilePath)
	if err != nil {
		return err
	}

	validationMaterial, err := getValidationMaterial(config.ValidationMaterialPath)
	if err != nil {
		return err
	}

	dc.rootSigner = key
	dc.rootCertificate = cert
	dc.validationBundle = validationMaterial

	return nil
}

func getRootKey(keyPath string) (crypto.Signer, error) {

	pkbytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	// assuming PEM encoded private key
	var blck *pem.Block
	blck, _ = pem.Decode(pkbytes)
	if blck == nil {
		return nil, errors.New("error decoding private key")
	}

	var key interface{}
	// parses uncrypted private key - returns any key
	key, err = x509.ParsePKCS8PrivateKey(blck.Bytes)
	if err != nil {
		return nil, err
	}

	switch keyType := key.(type) {
	case *rsa.PrivateKey:
		println("rsa key")
		return key.(*rsa.PrivateKey), nil
	case *ecdsa.PrivateKey:
		println("ecdsa key")
		return key.(*ecdsa.PrivateKey), nil
	case *ed25519.PrivateKey:
		println("ed25519 key")
		return key.(*ed25519.PrivateKey), nil
	default:
		return nil, fmt.Errorf("this type of key is not supported: %s", keyType)
	}

}

func getRootCert(certPath string) (*x509.Certificate, error) {
	certificateBytes, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	var blck *pem.Block
	blck, _ = pem.Decode(certificateBytes)
	if blck == nil {
		return nil, fmt.Errorf("error parsing block")
	}

	certificate, err := x509.ParseCertificate(blck.Bytes)
	if err != nil {
		return nil, err
	}
	return certificate, nil
}

func getValidationMaterial(path string) ([]*x509.Certificate, error) {
	var bundle []*x509.Certificate
	bundlebytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	for {
		var blck *pem.Block
		blck, bundlebytes = pem.Decode(bundlebytes)
		if blck == nil {
			break
		}

		cert, err := x509.ParseCertificate(blck.Bytes)
		if err != nil {
			break
		}

		if cert.IsCA {
			bundle = append(bundle, cert)
		}
	}
	return bundle, nil
}

func (dc *disk) RetrieveValidationMaterial() []*x509.Certificate {
	return dc.validationBundle
}

func (dc *disk) IssueSigningCertificate(params *X509CertificateParams) (*x509.Certificate, error) {

	template, err := createX509Template(params.PublicKey, params.Subject, params.URIs, params.TTL)
	if err != nil {
		return nil, fmt.Errorf("failed to create template for Server certificate: %w", err)
	}

	cert, err := signX509(template, dc.rootCertificate, dc.rootSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to sign X509 certificate: %w", err)
	}

	return cert, nil

}

func createX509Template(publicKey crypto.PublicKey, subject pkix.Name, uris []*url.URL, ttl time.Duration) (*x509.Certificate, error) {
	clock := clock.New()
	now := clock.Now()
	serial, err := newSerialNumber()
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		IsCA:                  false,
		NotBefore:             now,
		NotAfter:              now.Add(ttl),
		BasicConstraintsValid: true,
		PublicKey:             publicKey,
		URIs:                  uris,
	}

	template.KeyUsage = x509.KeyUsageKeyEncipherment |
		x509.KeyUsageKeyAgreement |
		x509.KeyUsageDigitalSignature
	template.ExtKeyUsage = []x509.ExtKeyUsage{
		x509.ExtKeyUsageCodeSigning,
	}

	return template, nil
}

// newSerialNumber returns a new random serial number in the range [1, 2^63-1].
func newSerialNumber() (*big.Int, error) {
	s, err := rand.Int(rand.Reader, getMaxBigInt64())
	if err != nil {
		return nil, fmt.Errorf("failed to create random number: %w", err)
	}

	return s.Add(s, big.NewInt(1)), nil
}

func getMaxBigInt64() *big.Int {
	return new(big.Int).SetInt64(1<<63 - 1)
}

func signX509(template, parent *x509.Certificate, signerPrivateKey crypto.PrivateKey) (*x509.Certificate, error) {
	var err error

	certData, err := x509.CreateCertificate(rand.Reader, template, parent, template.PublicKey, signerPrivateKey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil, err
	}

	return cert, nil
}
