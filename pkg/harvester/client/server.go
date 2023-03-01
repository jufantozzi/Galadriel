package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/HewlettPackard/galadriel/pkg/common"
	"github.com/HewlettPackard/galadriel/pkg/common/telemetry"

	"github.com/golang-jwt/jwt"
	"github.com/sirupsen/logrus"
)

const (
	contentType = "application/json"

	postBundlePath     = "/bundle"
	postBundleSyncPath = "/bundle/sync"
	onboardPath        = "/onboard"
	tokenPath          = "/token"
)

// GaladrielServerClient represents a client to connect to Galadriel Server
type GaladrielServerClient interface {
	SyncFederatedBundles(context.Context, *common.SyncBundleRequest) (*common.SyncBundleResponse, error)
	PostBundle(context.Context, *common.PostBundleRequest) error
	Connect(ctx context.Context, token string) error
	RefreshToken(ctx context.Context) error
	GetTokenTTL() time.Duration
}

type client struct {
	c       http.Client
	address string
	token   string
	logger  logrus.FieldLogger
}

func NewGaladrielServerClient(address, token, rootCAPath string) (GaladrielServerClient, error) {
	// Load the root CA certificate.
	caCert, err := os.ReadFile(rootCAPath)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	return &client{
		c: http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
					RootCAs:    caCertPool,
				},
			},
		},
		address: "https://" + address,
		token:   token,
		logger:  logrus.WithField(telemetry.SubsystemName, telemetry.GaladrielServerClient),
	}, nil
}

func (c *client) Connect(ctx context.Context, token string) error {
	url := c.address + onboardPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bodyString, err := readBody(resp)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to connect to Galadriel Server: %s", bodyString)
	}

	// validate token
	validJWT, err := c.validateJWT(bodyString)
	if err != nil {
		return err
	}

	c.token = validJWT

	c.logger.Info("Connected to Galadriel Server")
	return nil
}

// RefreshToken requests the Galadriel Server for a new JWT token if current token
// is older than its half-life time.
func (c *client) RefreshToken(ctx context.Context) error {
	token, _, err := new(jwt.Parser).ParseUnverified(c.token, jwt.MapClaims{})
	if err != nil {
		return fmt.Errorf("failed to parse JWT: %s", err.Error())
	}

	if !c.shouldRefresh(token) {
		return nil
	}

	url := c.address + tokenPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bodyString, err := readBody(resp)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to connect to Galadriel Server: %s", bodyString)
	}

	// validate token
	newToken, err := c.validateJWT(bodyString)
	if err != nil {
		return err
	}

	c.token = newToken

	c.logger.Info("Successfully refreshed JWT")
	return nil
}

func (c *client) GetTokenTTL() time.Duration {
	token, _, err := new(jwt.Parser).ParseUnverified(c.token, jwt.MapClaims{})
	if err != nil {
		// sanity check, this should be validated before being stored
		panic("invalid jwt after connecting")
	}

	iat := token.Claims.(jwt.MapClaims)["iat"].(float64)
	iatTime := time.Unix(int64(iat), 0)

	exp := token.Claims.(jwt.MapClaims)["exp"].(float64)
	expTime := time.Unix(int64(exp), 0)

	return expTime.Sub(iatTime)
}

func (c *client) SyncFederatedBundles(ctx context.Context, req *common.SyncBundleRequest) (*common.SyncBundleResponse, error) {
	b, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal federated bundle request: %v", err)
	}

	c.logger.Debugf("Sending post federated bundles updates:\n%s", b)
	url := c.address + postBundleSyncPath
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// TODO: decorate all requests coming out
	r.Header.Set("Authorization", "Bearer "+c.token)
	r.Header.Set("Content-Type", contentType)

	res, err := c.c.Do(r)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	// TODO: check right status code
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("request returned an error code %d: \n%s", res.StatusCode, body)
	}

	var syncBundleResponse common.SyncBundleResponse
	if err := json.Unmarshal(body, &syncBundleResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal sync bundle response: %v", err)
	}

	return &syncBundleResponse, nil
}

func (c *client) PostBundle(ctx context.Context, req *common.PostBundleRequest) error {
	b, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal push bundle request: %v", err)
	}

	url := c.address + postBundlePath

	r, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("failed to create push bundle request: %v", err)
	}

	// TODO: decorate all requests coming out
	r.Header.Set("Authorization", "Bearer "+c.token)
	r.Header.Set("Content-Type", contentType)

	res, err := c.c.Do(r)
	if err != nil {
		return fmt.Errorf("failed to send push bundle request: %v", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	// TODO: check right status code
	if res.StatusCode != 200 {
		return fmt.Errorf("push bundle request returned an error code %d: \n%s", res.StatusCode, body)
	}

	return nil
}

// shouldRefresh calculates if the received token is older than half its expiry date.
// Tokens older than half of their life should be renewed.
func (c *client) shouldRefresh(token *jwt.Token) bool {
	// calculate half-time
	now := time.Now()

	iat := token.Claims.(jwt.MapClaims)["iat"].(float64)
	iatTime := time.Unix(int64(iat), 0)

	exp := token.Claims.(jwt.MapClaims)["exp"].(float64)
	expTime := time.Unix(int64(exp), 0)

	halfLifeTime := expTime.Sub(iatTime) / 2
	duration := expTime.Sub(now)

	if duration > halfLifeTime {
		return false
	}

	return true
}

// validateJWT returns an error if the received token isn't a parseable JWT.
func (c *client) validateJWT(bodyString string) (string, error) {
	if len("Token: ") > len(bodyString) {
		return "", fmt.Errorf("error validating JWT: invalid response format: %s", bodyString)
	}

	receivedToken := bodyString[len("Token: "):]
	_, _, err := new(jwt.Parser).ParseUnverified(receivedToken, jwt.MapClaims{})
	if err != nil {
		return "", fmt.Errorf("failed to parse JWT: %s", err.Error())
	}

	return receivedToken, nil
}

func readBody(resp *http.Response) (string, error) {
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	bodyString := string(bodyBytes)
	return bodyString, nil
}
