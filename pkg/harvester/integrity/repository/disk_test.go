package repository

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
)

const (
	pathDir        = "/tmp"
	tempCAKeyFile  = "/rootsignCAkey.key"
	tempCACertFile = "/rootsignCAcert.crt"
	tmpCASubject   = "Galadriel Harv Signing CA"
)

func TestNew(t *testing.T) {
	_, err := New()
	assert.NoError(t, err)

}

func TestConfigure(t *testing.T) {
	config := loadConfig(pathDir)
	d, err := New()
	assert.NoError(t, err)
	err = d.Configure(&config)
	assert.NoError(t, err)
	// test path values
	assert.Equal(t, config.CertFilePath, pathDir+tempCACertFile)
	assert.Equal(t, config.KeyPath, pathDir+tempCAKeyFile)
	// test that the values are not nil
	assert.NotNil(t, d.rootSigner)
	assert.NotNil(t, d.rootCertificate)
	assert.NotNil(t, d.validationBundle)
	//test that the values are the root certificate subject is the expected one
	assert.Equal(t, tmpCASubject, d.rootCertificate.Subject.CommonName)
	// test that the root signer is the expected one
	assert.Equal(t, d.rootSigner.Public(), d.rootCertificate.PublicKey)

}

func TestConfigureEmpty(t *testing.T) {
	config := loadNilConfig()
	d, err := New()
	assert.NoError(t, err)
	err = d.Configure(&config)
	assert.Error(t, err)
	// test that the error is the expected one
	assert.Equal(t, "key path is not set", err.Error())

}

func TestIssueSigningCertificateRSA(t *testing.T) {
	err := CreateRootCARSA(pathDir, tempCAKeyFile, tempCACertFile)
	assert.NoError(t, err)

	config := loadConfig(pathDir)

	//create new disk
	d, err := New()
	assert.NoError(t, err)

	// configure the disk: load the paths into the disk structure
	err = d.Configure(&config)
	assert.NoError(t, err)

	//configure signer
	signer, err := rsa.GenerateKey(rand.Reader, 4096)
	assert.NoError(t, err)
	params := X509CertificateParams{
		PublicKey: signer.Public(),
		Subject:   pkix.Name{CommonName: "test"},
		URIs:      []*url.URL{spiffeid.RequireFromString("spiffe://domain/test").URL()},
		TTL:       time.Hour * 5,
	}

	cert, err := d.IssueSigningCertificate(&params)
	assert.NoError(t, err)
	assert.NotNil(t, cert)

	// test validity of cert with root, keyusage, and time
	rootCertPool := x509.NewCertPool()
	rootCertPool.AddCert(d.rootCertificate)

	_, err = cert.Verify(x509.VerifyOptions{
		Roots:     rootCertPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	assert.NoError(t, err)

	//test the cert was issued to sign
	assert.Contains(t, cert.ExtKeyUsage, x509.ExtKeyUsageCodeSigning)

	//test
	validationCerts := d.RetrieveValidationMaterial()
	assert.NotNil(t, validationCerts)

}

func TestIssueSigningCertificateECDSA(t *testing.T) {
	//createCA("EC", pathDir)
	err := CreateRootCAECDSA(pathDir, tempCAKeyFile, tempCACertFile)
	assert.NoError(t, err)

	config := loadConfig(pathDir)

	//create new disk
	d, err := New()
	assert.NoError(t, err)

	// configure the disk: load the paths into the disk structure
	err = d.Configure(&config)
	assert.NoError(t, err)

	signer, err := rsa.GenerateKey(rand.Reader, 4096)
	assert.NoError(t, err)
	params := X509CertificateParams{
		PublicKey: signer.Public(),
		Subject:   pkix.Name{CommonName: "test"},
		URIs:      []*url.URL{spiffeid.RequireFromString("spiffe://domain/test").URL()},
		TTL:       time.Hour * 5,
	}

	cert, err := d.IssueSigningCertificate(&params)
	assert.NoError(t, err)
	assert.NotNil(t, cert)

	// test validity of cert with root, keyusage, and time
	rootCertPool := x509.NewCertPool()
	rootCertPool.AddCert(d.rootCertificate)

	_, err = cert.Verify(x509.VerifyOptions{
		Roots:     rootCertPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	assert.NoError(t, err)

	//test the cert was issued to sign
	assert.Contains(t, cert.ExtKeyUsage, x509.ExtKeyUsageCodeSigning)

	//test that the validation material is not nil
	validationCerts := d.RetrieveValidationMaterial()
	assert.NotNil(t, validationCerts)

}

func loadConfig(pathDir string) Config {

	config := Config{
		CertFilePath: pathDir + tempCACertFile,
		KeyPath:      pathDir + tempCAKeyFile,
	}

	return config
}

func loadNilConfig() Config {
	config := Config{
		CertFilePath: "",
		KeyPath:      "",
	}

	return config
}
