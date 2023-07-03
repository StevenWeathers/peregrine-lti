package launch

import (
	"context"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/mitchellh/mapstructure"

	"github.com/stevenweathers/peregrine-lti/peregrine"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const (
	launchIDClaim            = "lti_launch_id"
	ltiDeploymentIdClaim     = "https://purl.imsglobal.org/spec/lti/claim/deployment_id"
	ltiMessageTypeClaim      = "https://purl.imsglobal.org/spec/lti/claim/message_type"
	ltiMessageTypeClaimValue = "LtiResourceLinkRequest"
	ltiVersionClaim          = "https://purl.imsglobal.org/spec/lti/claim/version"
	ltiVersionClaimValue     = "1.3.0"
	ltiTargetLinkUriClaim    = "https://purl.imsglobal.org/spec/lti/claim/target_link_uri"
	nonceClaim               = "nonce"
)

func validateLoginRequestParams(params peregrine.OIDCLoginRequestParams) error {
	if params.Issuer == "" {
		return fmt.Errorf("MISSING_ISS")
	}
	if params.ClientID == "" {
		return fmt.Errorf("MISSING_CLIENT_ID")
	}
	if params.LoginHint == "" {
		return fmt.Errorf("MISSING_LOGIN_HINT")
	}
	if params.TargetLinkURI == "" {
		return fmt.Errorf("MISSING_TARGET_LINK_URI")
	}

	return nil
}

// validateState parses the jwt with the configured key and returns the Launch.ID from the jwt claims
func validateState(jwtKeySecret string, state string) (uuid.UUID, error) {
	launchID := uuid.New()

	key, err := jwk.FromRaw([]byte(jwtKeySecret))
	if err != nil {
		return launchID, fmt.Errorf("failed to create JWK key with configured secret: %v", err)
	}

	verifiedToken, err := jwt.Parse([]byte(state), jwt.WithKey(jwa.HS256, key))
	if err != nil {
		return launchID, fmt.Errorf("failed to verify JWS: %v", err)
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

// parseIDToken validates the id_token jwt with the peregrine.Platform key set returning peregrine.LTI1p3Claims
func parseIDToken(ctx context.Context, jwkCache *jwk.Cache, launch peregrine.Launch, idToken string) (peregrine.LTI1p3Claims, error) {
	var lti1p3Claims peregrine.LTI1p3Claims
	keysetUrl := launch.Registration.Platform.KeySetURL

	keySet, err := getPlatformJWKs(ctx, jwkCache, keysetUrl)
	if err != nil {
		return lti1p3Claims, fmt.Errorf("unable to retrieve %s keyset: %v", keysetUrl, err)
	}

	// validate that the id_token jwt is can be parsed and return a verified token
	// including verifying the issuer and client_id from peregrine.Launch.Platform
	// as well as checking for LTI 1.3 required claims
	verifiedToken, err := jwt.Parse([]byte(idToken), jwt.WithKeySet(keySet),
		jwt.WithIssuer(launch.Registration.Platform.Issuer),
		jwt.WithAudience(launch.Registration.ClientID),
		jwt.WithClaimValue(nonceClaim, launch.Nonce.String()),
		jwt.WithRequiredClaim(ltiDeploymentIdClaim),
		jwt.WithClaimValue(ltiMessageTypeClaim, ltiMessageTypeClaimValue),
		jwt.WithClaimValue(ltiVersionClaim, ltiVersionClaimValue),
		jwt.WithRequiredClaim(ltiTargetLinkUriClaim),
	)
	if err != nil {
		return lti1p3Claims, fmt.Errorf("invalid id_token: %v", err)
	}

	cfg := &mapstructure.DecoderConfig{
		Metadata: nil,
		Result:   &lti1p3Claims,
		TagName:  "json",
	}
	decoder, _ := mapstructure.NewDecoder(cfg)
	err = decoder.Decode(verifiedToken.PrivateClaims())
	if err != nil {
		return lti1p3Claims, fmt.Errorf("failed to decode LTI claims %v", err)
	}
	lti1p3Claims.SUB = verifiedToken.Subject()

	if lti1p3Claims.SUB != "" && (len(lti1p3Claims.SUB) > 255) {
		return lti1p3Claims, fmt.Errorf("sub %s in id_token exceeds 255 characters", lti1p3Claims.SUB)
	}

	// validate deployment_id exists and if launch had deployment_id that it matches
	if launch.Deployment != nil && lti1p3Claims.DeploymentID != launch.Deployment.PlatformDeploymentID {
		return lti1p3Claims, fmt.Errorf(
			"launch platform_deployment_id %s does not match id_token deployment_id %s",
			launch.Deployment.PlatformDeploymentID, lti1p3Claims.DeploymentID,
		)
	}

	return lti1p3Claims, nil
}
