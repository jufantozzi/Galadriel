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

const pathDir = "/tmp"

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
	assert.NotNil(t, d.rootSigner)
	assert.NotNil(t, d.rootCertificate)
	assert.NotNil(t, d.validationBundle)

}

func TestConfigureEmpty(t *testing.T) {
	config := loadNilConfig()
	d, err := New()
	assert.NoError(t, err)
	err = d.Configure(&config)
	assert.Error(t, err)

}

func TestIssueSigningCertificateRSA(t *testing.T) {
	err := CreateRootCARSA(pathDir)
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
	assert.Contains(t, validationCerts, d.rootCertificate)

}

func TestIssueSigningCertificateECDSA(t *testing.T) {
	//createCA("EC", pathDir)
	err := CreateRootCAECDSA(pathDir)
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

	//test
	validationCerts := d.RetrieveValidationMaterial()
	assert.NotNil(t, validationCerts)
	assert.Contains(t, validationCerts, d.rootCertificate)

}

func loadConfig(pathDir string) Config {

	config := Config{
		CertFilePath: pathDir + "/rootsignCAcert.crt",
		KeyPath:      pathDir + "/rootsignCAkey.key",
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
