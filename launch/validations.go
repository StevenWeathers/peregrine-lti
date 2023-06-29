package launch

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"log"
	"time"

	"github.com/stevenweathers/peregrine-lti/peregrine"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const launchIDClaim = "lti_launch_id"

func validateLoginRequestParams(params peregrine.OIDCLoginRequestParams) error {
	if params.Issuer == "" {
		return fmt.Errorf("missing iss")
	}
	if params.ClientID == "" {
		return fmt.Errorf("missing client_id")
	}
	if params.LoginHint == "" {
		return fmt.Errorf("missing login_hint")
	}
	if params.TargetLinkURI == "" {
		return fmt.Errorf("missing target_link_uri")
	}

	return nil
}

// getPlatformJWKs retrieves the platforms jwk key set used to parse the oidc id_token jwt
// caching the jwk key set in memory to improve performance
func (s *Service) getPlatformJWKs(ctx context.Context, jwkURL string) (jwk.Set, error) {
	if !s.jwkCache.IsRegistered(jwkURL) {
		_ = s.jwkCache.Register(jwkURL)
		if _, err := s.jwkCache.Refresh(ctx, jwkURL); err != nil {
			return nil, err
		}
	}
	return s.jwkCache.Get(ctx, jwkURL)
}

// createLaunchState builds a jwt to act as the state value for the oidc login flow returning jwt as a string
func (s *Service) createLaunchState(launchID uuid.UUID) (string, error) {
	var state string
	// Build a JWT!
	tok, err := jwt.NewBuilder().
		Issuer(s.config.Issuer).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Minute*10)).
		Claim(launchIDClaim, launchID.String()).
		Build()
	if err != nil {
		return state, err
	}

	key, err := jwk.FromRaw([]byte(s.config.JWTKeySecret))
	if err != nil {
		return state, err
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256, key))
	if err != nil {
		return state, err
	}

	state = string(signed)

	return state, nil
}

// validateState parses the jwt with the configured key and returns the Launch.ID from the jwt claims
func (s *Service) validateState(state string) (uuid.UUID, error) {
	launchID := uuid.New()

	key, err := jwk.FromRaw([]byte(s.config.JWTKeySecret))
	if err != nil {
		return launchID, err
	}

	verifiedToken, err := jwt.Parse([]byte(state), jwt.WithKey(jwa.HS256, key))
	if err != nil {
		return launchID, fmt.Errorf("failed to verify JWS: %s\n", err)
	}
	claims := verifiedToken.PrivateClaims()
	lid, ok := claims[launchIDClaim]
	if !ok {
		return launchID, fmt.Errorf("%s claim not found in launch state jwt", launchIDClaim)
	}
	launchID, err = uuid.Parse(lid.(string))
	if err != nil {
		return launchID, fmt.Errorf("%s claim not a uuid", launchIDClaim)
	}

	return launchID, nil
}

// parseIDToken validates the id_token jwt with the peregrine.Platform keyset returning peregrine.LTI1p3Claims
func (s *Service) parseIDToken(ctx context.Context, launch peregrine.Launch, idToken string) (peregrine.LTI1p3Claims, error) {
	var lti1p3Claims peregrine.LTI1p3Claims
	keysetUrl := launch.Registration.Platform.KeySetURL

	keySet, err := s.getPlatformJWKs(ctx, keysetUrl)
	if err != nil {
		return lti1p3Claims, fmt.Errorf("unable to retrieve %s keyset: %v", keysetUrl, err)
	}

	// validate that the id_token jwt is can be parsed and return a verified token
	// including verifying the issuer and client_id from peregrine.Launch.Platform
	// as well as checking for LTI 1.3 required claims
	verifiedToken, err := jwt.Parse([]byte(idToken), jwt.WithKeySet(keySet),
		jwt.WithIssuer(launch.Registration.Platform.Issuer),
		jwt.WithAudience(launch.Registration.ClientID),
		jwt.WithClaimValue("nonce", launch.Nonce.String()),
		jwt.WithRequiredClaim("https://purl.imsglobal.org/spec/lti/claim/deployment_id"),
		jwt.WithClaimValue("https://purl.imsglobal.org/spec/lti/claim/message_type", "LtiResourceLinkRequest"),
		jwt.WithClaimValue("https://purl.imsglobal.org/spec/lti/claim/version", "1.3.0"),
		jwt.WithRequiredClaim("https://purl.imsglobal.org/spec/lti/claim/target_link_uri"),
	)
	if err != nil {
		return lti1p3Claims, fmt.Errorf("invalid id_token")
	}

	jsonData, err := json.Marshal(verifiedToken.PrivateClaims())
	if err != nil {
		log.Fatal(err)
	}

	err = json.Unmarshal(jsonData, &lti1p3Claims)
	if err != nil {
		return lti1p3Claims, fmt.Errorf("failed to decode LTI claims %v", err)
	}

	// @TODO - how to handle azp?

	if lti1p3Claims.SUB != "" && (len(lti1p3Claims.SUB) > 255) {
		return lti1p3Claims, fmt.Errorf("sub %s in id_token exceeds 255 characters", lti1p3Claims.SUB)
	}

	// validate deployment_id exists and if launch had deployment_id that it matches
	if launch.Deployment != nil && lti1p3Claims.DeploymentID != launch.Deployment.ID.String() {
		return lti1p3Claims, fmt.Errorf(
			"launch deployment_id %s does not match id_token deployment_id %s",
			launch.Deployment.ID.String(), lti1p3Claims.DeploymentID,
		)
	} else {
		deployment, err := s.dataSvc.GetDeploymentByPlatformDeploymentID(ctx, lti1p3Claims.DeploymentID)
		if err != nil {
			return lti1p3Claims, fmt.Errorf(
				"lms deployment_id %s not found in tool lti data source",
				lti1p3Claims.DeploymentID,
			)
		}
		launch.Deployment = &deployment
	}

	if lti1p3Claims.ToolPlatform.GUID != "" {
		platformInstance, err := s.dataSvc.GetPlatformInstanceByGUID(ctx, lti1p3Claims.ToolPlatform.GUID)
		if err != nil {
			return lti1p3Claims, err
		}
		launch.PlatformInstance = &platformInstance
	}

	used := time.Now()
	launch.Used = &used
	_, err = s.dataSvc.UpdateLaunch(ctx, launch)
	if err != nil {
		return lti1p3Claims, err
	}

	return lti1p3Claims, nil
}
