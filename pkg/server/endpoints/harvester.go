package endpoints

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/HewlettPackard/galadriel/pkg/common/entity"
	"github.com/google/uuid"
	"io"
	"strings"

	"github.com/HewlettPackard/galadriel/pkg/common"
	"github.com/HewlettPackard/galadriel/pkg/common/util"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const (
	tokenKey       = "token"
	spiffeIDPrefix = "spiffe://"
)

func (e *Endpoints) onboardHandler(ctx echo.Context) error {
	// authenticate join token
	authHeader := ctx.Request().Header.Get(echo.HeaderAuthorization)
	if !strings.Contains(authHeader, "Bearer ") {
		err := errors.New("auth error: bad authorization header: " + authHeader)
		e.Logger.Error(err)
		return err
	}

	jtString := authHeader[len("Bearer "):]
	jt, err := e.Datastore.FindJoinToken(context.TODO(), jtString)
	if err != nil {
		e.Logger.Errorf("invalid token: %s\n", jt)
		return err
	}
	e.Logger.Debugf("Token valid for trust domain: %v\n", jt)

	authenticatedTD, err := e.Datastore.FindTrustDomainByID(ctx.Request().Context(), jt.TrustDomainID)

	// generate and sign JWT
	signedJWT, err := util.GenerateJWT(util.GenerateJWTClaims(authenticatedTD.Name.String(), e.JWT.TokenTTL), e.JWT.Key)
	if err != nil {
		e.Logger.Errorf("failed generating JWT: %v\n", err)
		return err
	}

	_, err = ctx.Response().Write([]byte("Token: " + signedJWT))
	if err != nil {
		e.Logger.Errorf("failed responding to harvester: %s\n", err.Error())
		return err
	}

	e.Logger.Info("Harvester connected")
	return nil
}

func (e *Endpoints) refreshJWTHandler(ctx echo.Context) error {
	t, ok := ctx.Get(tokenKey).(*jwt.Token)
	if !ok {
		err := errors.New("error asserting harvester's JWT")
		e.handleTCPError(ctx, err.Error())
		return err
	}

	var authenticatedTrustDomain string
	if claims, ok := t.Claims.(jwt.MapClaims); ok {
		authenticatedTrustDomain, ok = claims["trust-domain"].(string)
		if !ok {
			err := errors.New("error asserting trust-domain from JWT claims")
			e.handleTCPError(ctx, err.Error())
			return err
		}
	}

	id, err := spiffeid.FromString(fmt.Sprintf("%s%s", spiffeIDPrefix, authenticatedTrustDomain))
	if err != nil {
		e.handleTCPError(ctx, fmt.Sprintf("failed to create spiffeID '%s': %v", authenticatedTrustDomain, err))
		return err
	}

	// generate and sign JWT
	jwtClaims := util.GenerateJWTClaims(id.TrustDomain().String(), e.JWT.TokenTTL)
	signedToken, err := util.GenerateJWT(jwtClaims, e.JWT.Key)
	if err != nil {
		err := fmt.Errorf("failed generating JWT: %v\n", err)
		e.handleTCPError(ctx, err.Error())
		return err
	}

	_, err = ctx.Response().Write([]byte("Token: " + signedToken))
	if err != nil {
		err := fmt.Errorf("failed responding to harvester: %w\n", err)
		e.handleTCPError(ctx, err.Error())
		return err
	}

	e.Logger.WithField("trust-domain", id.TrustDomain().String()).Debugf("Successfully rotated JWT")

	return nil
}

func (e *Endpoints) postBundleHandler(ctx echo.Context) error {
	e.Logger.Debug("Receiving post bundle request")

	// TODO: refactor into assertToken() or smt
	t, ok := ctx.Get("token").(*jwt.Token)
	if !ok {
		err := errors.New("error asserting harvester's JWT")
		e.handleTCPError(ctx, err.Error())
		return err
	}
	var td string
	if claims, ok := t.Claims.(jwt.MapClaims); ok {
		td = claims["trust-domain"].(string)
	}

	authenticatedSpiffeID, err := spiffeid.FromString(fmt.Sprintf("%s%s", spiffeIDPrefix, td))
	if err != nil {
		e.handleTCPError(ctx, fmt.Sprintf("failed to create spiffeID '%s': %v", authenticatedSpiffeID, err))
		return err
	}

	authenticatedTD, err := e.Datastore.FindTrustDomainByName(ctx.Request().Context(), authenticatedSpiffeID.TrustDomain())

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

	if harvesterReq.TrustDomainName != authenticatedSpiffeID.TrustDomain() {
		err := fmt.Errorf(
			"authenticated trust domain {%s} does not match trust domain in request: {%s}",
			harvesterReq.TrustDomainID, authenticatedSpiffeID.TrustDomain())
		e.handleTCPError(ctx, err.Error())
		return err
	}

	bundle, err := spiffebundle.Parse(authenticatedSpiffeID.TrustDomain(), harvesterReq.Bundle.Data)
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
			ID:            currentStoredBundle.ID,
			Data:          harvesterReq.Bundle.Data,
			Digest:        harvesterReq.Bundle.Digest,
			TrustDomainID: authenticatedTD.ID.UUID,
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
			e.handleTCPError(ctx, fmt.Sprintf("failed to create trustDomain: %v", err))
			return err
		}

		e.Logger.Debugf("Trust domain %s has been successfully updated", harvesterReq.TrustDomainName)
	}

	return nil
}

func (e *Endpoints) syncFederatedBundleHandler(ctx echo.Context) error {
	e.Logger.Debug("Receiving sync request")

	t, ok := ctx.Get("token").(*jwt.Token)
	if !ok {
		err := errors.New("error asserting harvester's JWT")
		e.handleTCPError(ctx, err.Error())
		return err
	}
	var td string
	if claims, ok := t.Claims.(jwt.MapClaims); ok {
		td = claims["trust-domain"].(string)
	}

	authenticatedSpiffeID, err := spiffeid.FromString(fmt.Sprintf("%s%s", spiffeIDPrefix, td))
	if err != nil {
		e.handleTCPError(ctx, fmt.Sprintf("failed to create spiffeID '%s': %v", authenticatedSpiffeID, err))
		return err
	}

	authenticatedTD, err := e.Datastore.FindTrustDomainByName(ctx.Request().Context(), authenticatedSpiffeID.TrustDomain())

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
	e.Logger.Debugf("Incoming sync request state: %v", harvesterBundleDigests)

	_, foundSelf := receivedHarvesterState.State[authenticatedTD.Name]
	if foundSelf {
		e.handleTCPError(ctx, "bad request: harvester cannot federate with itself")
		return err
	}

	relationships, err := e.Datastore.FindRelationshipsByTrustDomainID(ctx.Request().Context(), authenticatedTD.ID.UUID)
	if err != nil {
		e.handleTCPError(ctx, fmt.Sprintf("failed to fetch relationships: %v", err))
		return err
	}

	federatedTDs := getFederatedTrustDomains(relationships, authenticatedTD.ID.UUID)

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
		response := common.SyncBundleResponse{}

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

func (e *Endpoints) validateToken(ctx echo.Context, t string) (bool, error) {
	parsedToken, err := jwt.Parse(t, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("auth error: unexpected jwt signing method: %v", t.Header["alg"])
		}

		return e.JWT.Key.Public(), nil
	})
	if err != nil {
		err := errors.New("auth error: error parsing harvester JWT token: " + err.Error())
		e.handleTCPError(ctx, err.Error())
		return false, err
	}

	if err := parsedToken.Claims.Valid(); err != nil {
		return false, fmt.Errorf("auth error: invalid token: %v", err)
	}

	e.Logger.Debugf("Setting token for request: %v", parsedToken.Claims)
	ctx.Set("token", parsedToken)

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
