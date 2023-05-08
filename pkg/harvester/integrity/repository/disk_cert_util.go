package repository

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

const (
	textCert          = "CERTIFICATE"
	textRSAPrivateKey = "RSA PRIVATE KEY"
)

func CreateRootCARSA(tempDir string, tempKeyFile string, tempCertFile string) error {

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	template := createTemplateCA()

	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}

	err = writeKeyToFile(keyBytes, tempDir, tempKeyFile)
	if err != nil {
		return err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}

	err = writeCertToFile(certBytes, tempDir, tempCertFile)
	if err != nil {
		return err
	}

	return nil
}

func CreateRootCAECDSA(tempDir string, tempKeyFile string, tempCertFile string) error {

	curve := elliptic.P256()
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return err
	}
	template := createTemplateCA()

	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}

	err = writeKeyToFile(keyBytes, tempDir, tempKeyFile)
	if err != nil {
		return err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}

	err = writeCertToFile(certBytes, tempDir, tempCertFile)
	if err != nil {
		return err
	}

	return nil
}

// newSerialNumber returns a new random serial number in the range [1, 2^63-1].
func NewSerialNumber() (*big.Int, error) {
	s, err := rand.Int(rand.Reader, getMaxBigInt64())
	if err != nil {
		return nil, fmt.Errorf("failed to create random number: %w", err)
	}

	return s.Add(s, big.NewInt(1)), nil
}

func getMaxBigInt64() *big.Int {
	return new(big.Int).SetInt64(1<<63 - 1)
}

func createTemplateCA() x509.Certificate {
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Galadriel Harv Signing CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	return template
}

func writeKeyToFile(keyBytes []byte, tempDir string, tempKeyFile string) error {
	keyFile, err := os.Create(tempDir + tempKeyFile)
	if err != nil {
		return err
	}

	defer keyFile.Close()
	err = pem.Encode(keyFile, &pem.Block{Type: textRSAPrivateKey, Bytes: keyBytes})
	if err != nil {
		return err
	}

	return nil
}

func writeCertToFile(certBytes []byte, tempDir string, tempCertFile string) error {
	certFile, err := os.Create(tempDir + tempCertFile)
	if err != nil {
		return err
	}

	defer certFile.Close()
	err = pem.Encode(certFile, &pem.Block{Type: textCert, Bytes: certBytes})
	if err != nil {
		return err
	}

	return nil
}