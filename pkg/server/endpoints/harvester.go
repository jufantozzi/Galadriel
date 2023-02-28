package endpoints

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/HewlettPackard/galadriel/pkg/common"
	"github.com/HewlettPackard/galadriel/pkg/common/entity"
	"github.com/HewlettPackard/galadriel/pkg/common/util"

	"github.com/google/uuid"
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const tokenKey = "token"

func (e *Endpoints) onboardHandler(ctx echo.Context) error {
	// authenticate join token
	authHeader := ctx.Request().Header.Get(echo.HeaderAuthorization)
	if !strings.Contains(authHeader, "Bearer ") {
		err := errors.New("auth error: bad authorization header: " + authHeader)
		e.Logger.Error(err)
		return err
	}

	token := authHeader[len("Bearer "):]
	t, err := e.DataStore.GetAccessToken(context.TODO(), token)
	if err != nil {
		e.Logger.Errorf("invalid token: %s\n", token)
		return err
	}
	e.Logger.Debugf("Token valid for trust domain: %s\n", t.TrustDomain)

	// generate and sign JWT
	signedToken, err := util.GenerateJWT(util.GenerateJWTClaims(t.TrustDomain.String(), defaultJWTExpiry), e.JWTKey)
	if err != nil {
		e.Logger.Errorf("failed generating JWT: %v\n", err)
		return err
	}

	_, err = ctx.Response().Write([]byte("Token: " + signedToken))
	if err != nil {
		e.Logger.Errorf("failed responding to harvester: %s\n", token)
		return err
	}

	e.Logger.Info("Harvester connected")
	return nil
}

func (e *Endpoints) refreshJWTHandler(ctx echo.Context) error {
	token, ok := ctx.Get("token").(*jwt.Token)
	if !ok {
		err := errors.New("error asserting harvester's JWT")
		e.handleTcpError(ctx, err.Error())
		return err
	}

	signedToken, err := util.GenerateJWT(util.GenerateJWTClaims(t.TrustDomain.String(), defaultJWTExpiry), key)

	id, err := spiffeid.FromString(fmt.Sprintf("spiffe://%s", authenticatedTrustDomain))
	if err != nil {
		e.handleTcpError(ctx, fmt.Sprintf("failed to create spiffeID '%s': %v", authenticatedTrustDomain, err))
		return err
	}
	// generate and sign JWT
	signedToken, err := util.GenerateJWT(util.GenerateJWTClaims(id.TrustDomain().String(), defaultJWTExpiry), e.JWTKey)
	if err != nil {
		e.Logger.Errorf("failed generating JWT: %v\n", err)
		return err
	}

	e.Logger.Infof("Sending token: %s", "Token: "+signedToken)

	_, err = ctx.Response().Write([]byte("Token: " + signedToken))
	if err != nil {
		e.Logger.Errorf("failed responding to harvester: %s\n", token)
		return err
	}

	return nil
}

func (e *Endpoints) postBundleHandler(ctx echo.Context) error {
	e.Logger.Debug("Receiving post bundle request")

	token, ok := ctx.Get("token").(*jwt.Token)
	if !ok {
		err := errors.New("error asserting harvester's JWT")
		e.handleTcpError(ctx, err.Error())
		return err
	}
	var authenticatedTrustDomain string
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		authenticatedTrustDomain = claims["trust-domain"].(string)
	}

	id, err := spiffeid.FromString(fmt.Sprintf("spiffe://%s", authenticatedTrustDomain))
	if err != nil {
		e.handleTcpError(ctx, fmt.Sprintf("failed to create spiffeID '%s': %v", authenticatedTrustDomain, err))
		return err
	}

	body, err := io.ReadAll(ctx.Request().Body)
	if err != nil {
		e.handleTCPError(ctx, fmt.Sprintf("failed to read body: %v", err))
		return err
	}

	harvesterReq := common.PostBundleRequest{}
	err = json.Unmarshal(body, &harvesterReq)
	if err != nil {
		e.handleTCPError(ctx, fmt.Sprintf("failed to unmarshal state: %v", err))
		return err
	}

	if harvesterReq.TrustDomainName != authenticatedTD.Name {
		err := fmt.Errorf("authenticated trust domain {%s} does not match trust domain in request: {%s}", harvesterReq.TrustDomainID, token.TrustDomainID)
		e.handleTCPError(ctx, err.Error())
		return err
	}

	bundle, err := spiffebundle.Parse(authenticatedTD.Name, harvesterReq.Bundle.Data)
	if err != nil {
		e.handleTCPError(ctx, fmt.Sprintf("failed to parse bundle: %v", err))
		return err
	}

	x509b, err := bundle.X509Bundle().Marshal()
	if err != nil {
		e.handleTCPError(ctx, fmt.Sprintf("failed to marshal bundle: %v", err))
		return err
	}

	digest := util.GetDigest(x509b)

	if !bytes.Equal(harvesterReq.Digest, digest) {
		err := errors.New("calculated digest does not match received digest")
		e.handleTCPError(ctx, err.Error())
		return err
	}

	currentStoredBundle, err := e.Datastore.FindBundleByTrustDomainID(ctx.Request().Context(), authenticatedTD.ID.UUID)
	if err != nil {
		e.handleTCPError(ctx, err.Error())
		return err
	}

	if harvesterReq.Bundle != nil && currentStoredBundle != nil && !bytes.Equal(harvesterReq.Bundle.Digest, currentStoredBundle.Digest) {
		_, err := e.Datastore.CreateOrUpdateBundle(ctx.Request().Context(), &entity.Bundle{
			Data: harvesterReq.Bundle.Data,
		})
		if err != nil {
			e.handleTCPError(ctx, fmt.Sprintf("failed to update trustDomain: %v", err))
			return err
		}

		e.Logger.Infof("Trust domain %s has been successfully updated", authenticatedTD.Name)
	} else if currentStoredBundle == nil {
		_, err := e.Datastore.CreateOrUpdateBundle(ctx.Request().Context(), &entity.Bundle{
			Data:          harvesterReq.Bundle.Data,
			Digest:        harvesterReq.Bundle.Digest,
			TrustDomainID: authenticatedTD.ID.UUID,
		})
		if err != nil {
			e.handleTCPError(ctx, fmt.Sprintf("failed to update trustDomain: %v", err))
			return err
		}

		e.Logger.Debugf("Trust domain %s has been successfully updated", harvesterReq.TrustDomainName)
	}

	return nil
}

func (e *Endpoints) syncFederatedBundleHandler(ctx echo.Context) error {
	e.Logger.Debug("Receiving sync request")

	token, ok := ctx.Get("token").(*jwt.Token)
	if !ok {
		err := errors.New("error parsing JWT")
		e.handleTCPError(ctx, err.Error())
		return err
	}

	harvesterTrustDomain, err := e.Datastore.FindTrustDomainByID(ctx.Request().Context(), token.TrustDomainID)
	if err != nil {
		e.handleTCPError(ctx, fmt.Sprintf("failed to read body: %v", err))
		return err
	}
	var authenticatedTrustDomain string
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		authenticatedTrustDomain = claims["trust-domain"].(string)
	}

	id, err := spiffeid.FromString(fmt.Sprintf("spiffe://%s", authenticatedTrustDomain))
	if err != nil {
		e.handleTcpError(ctx, fmt.Sprintf("failed to create spiffeID '%s': %v", authenticatedTrustDomain, err))
		return err
	}

	body, err := io.ReadAll(ctx.Request().Body)
	if err != nil {
		e.handleTCPError(ctx, fmt.Sprintf("failed to read body: %v", err))
		return err
	}

	receivedHarvesterState := common.SyncBundleRequest{}
	err = json.Unmarshal(body, &receivedHarvesterState)
	if err != nil {
		e.handleTCPError(ctx, fmt.Sprintf("failed to unmarshal state: %v", err))
		return err
	}

	harvesterBundleDigests := receivedHarvesterState.State

	_, foundSelf := receivedHarvesterState.State[harvesterTrustDomain.Name]
	if foundSelf {
		e.handleTCPError(ctx, "bad request: harvester cannot federate with itself")
		return err
	}

	relationships, err := e.Datastore.FindRelationshipsByTrustDomainID(ctx.Request().Context(), harvesterTrustDomain.ID.UUID)
	if err != nil {
		e.handleTCPError(ctx, fmt.Sprintf("failed to fetch relationships: %v", err))
		return err
	}

	federatedTDs := getFederatedTrustDomains(relationships, harvesterTrustDomain.ID.UUID)

	if len(federatedTDs) == 0 {
		e.Logger.Debug("No federated trust domains yet")
		return nil
	}

	federatedBundles, federatedBundlesDigests, err := e.getCurrentFederatedBundles(ctx.Request().Context(), federatedTDs)
	if err != nil {
		e.handleTCPError(ctx, fmt.Sprintf("failed to fetch bundles from DB: %v", err))
		return err
	}

	if len(federatedBundles) == 0 {
		e.Logger.Debug("No federated bundles yet")
		return nil
	}

	bundlesUpdates, err := e.getFederatedBundlesUpdates(ctx.Request().Context(), harvesterBundleDigests, federatedBundles)
	if err != nil {
		e.handleTCPError(ctx, fmt.Sprintf("failed to fetch bundles from DB: %v", err))
		return err
	}

	response := common.SyncBundleResponse{
		Updates: bundlesUpdates,
		State:   federatedBundlesDigests,
	}

	responseBytes, err := json.Marshal(response)
	if err != nil {
		e.handleTCPError(ctx, fmt.Sprintf("failed to marshal response: %v", err))
		return err
	}

	_, err = ctx.Response().Write(responseBytes)
	if err != nil {
		e.handleTCPError(ctx, fmt.Sprintf("failed to write response: %v", err))
		return err
	}

	return nil
}

func (e *Endpoints) validateToken(ctx echo.Context, token string) (bool, error) {
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("auth error: unexpected jwt signing method: %v", token.Header["alg"])
		}

		return e.JWTKey.Public(), nil
	})
	if err != nil {
		err := errors.New("auth error: error parsing harvester JWT token: " + err.Error())
		e.handleTcpError(ctx, err.Error())
		return false, err
	}

	if err := parsedToken.Claims.Valid(); err != nil {
		return false, fmt.Errorf("auth error: invalid token: %v", err)
	}

	ctx.Set("token", parsedToken)

	e.Logger.Debugf("Parsed token: %v", *parsedToken)

	return true, nil
}

func getFederatedTrustDomains(relationships []*entity.Relationship, tdID uuid.UUID) []uuid.UUID {
	var federatedTrustDomains []uuid.UUID

	for _, r := range relationships {
		ma := r.TrustDomainAID
		mb := r.TrustDomainBID

		if tdID == ma {
			federatedTrustDomains = append(federatedTrustDomains, mb)
		} else {
			federatedTrustDomains = append(federatedTrustDomains, ma)
		}
	}
	return federatedTrustDomains
}

func (e *Endpoints) getFederatedBundlesUpdates(ctx context.Context, harvesterBundlesDigests common.BundlesDigests, federatedBundles []*entity.Bundle) (common.BundleUpdates, error) {
	response := make(common.BundleUpdates)

	for _, b := range federatedBundles {
		td, err := e.Datastore.FindTrustDomainByID(ctx, b.TrustDomainID)
		if err != nil {
			return nil, err
		}

		serverDigest := b.Digest
		harvesterDigest := harvesterBundlesDigests[td.Name]

		// If the bundle digest received from a federated trust domain of the calling harvester is not the same as the
		// digest the server has, the harvester needs to be updated of the new bundle. This also covers the case of
		// the harvester not being aware of any bundles. The update represents a newly federated trustDomain's bundle.
		if !bytes.Equal(harvesterDigest, serverDigest) {
			response[td.Name] = b
		}
	}

	return response, nil
}

func (e *Endpoints) getCurrentFederatedBundles(ctx context.Context, federatedTDs []uuid.UUID) ([]*entity.Bundle, common.BundlesDigests, error) {
	var bundles []*entity.Bundle
	bundlesDigests := map[spiffeid.TrustDomain][]byte{}

	for _, id := range federatedTDs {
		b, err := e.Datastore.FindBundleByTrustDomainID(ctx, id)
		if err != nil {
			return nil, nil, err
		}
		td, err := e.Datastore.FindTrustDomainByID(ctx, id)
		if err != nil {
			return nil, nil, err
		}

		if b != nil {
			bundles = append(bundles, b)
			bundlesDigests[td.Name] = b.Digest
		}
	}

	return bundles, bundlesDigests, nil
}

func (e *Endpoints) handleTCPError(ctx echo.Context, errMsg string) {
	e.Logger.Errorf(errMsg)
	_, err := ctx.Response().Write([]byte(errMsg))
	if err != nil {
		e.Logger.Errorf("Failed to write error response: %v", err)
	}
}
