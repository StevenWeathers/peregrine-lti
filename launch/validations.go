package launch

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/stevenweathers/peregrine-lti/peregrine"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
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

	// @TODO - replace this temporary private key with a configurable key solution
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return state, err
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, key))
	if err != nil {
		return state, err
	}

	state = string(signed)

	return state, nil
}

// validateState parses the jwt with the configured key and returns the Launch.ID from the jwt claims
func (s *Service) validateState(state string) (uuid.UUID, error) {
	launchID := uuid.New()
	// @TODO - replace key string with public key from configured key
	verifiedToken, err := jwt.Parse([]byte(state), jwt.WithKey(jwa.RS256, ""))
	if err != nil {
		return launchID, fmt.Errorf("failed to verify JWS: %s\n", err)
	}
	claims := verifiedToken.PrivateClaims()
	lid, ok := claims[launchIDClaim]
	if !ok {
		return launchID, fmt.Errorf("%s claim not found in launch state jwt", launchIDClaim)
	}
	launchID = lid.(uuid.UUID)

	return launchID, nil
}

// parseIDToken validates the id_token jwt with the peregrine.Platform keyset returning peregrine.LTI1p3Claims
func (s *Service) parseIDToken(ctx context.Context, launch peregrine.Launch, idToken string) (peregrine.LTI1p3Claims, error) {
	idt := peregrine.LTI1p3Claims{}
	keysetUrl := launch.Registration.Platform.KeySetURL

	keySet, err := s.getPlatformJWKs(ctx, keysetUrl)
	if err != nil {
		return idt, fmt.Errorf("unable to retrieve %s keyset: %v", keysetUrl, err)
	}

	// validate that the id_token jwt is can be parsed and return a verified token
	// including verifying the issuer and client_id from peregrine.Launch.Platform
	verifiedToken, err := jwt.Parse(
		[]byte(idToken), jwt.WithKeySet(keySet), jwt.WithIssuer(launch.Registration.Platform.Issuer),
		jwt.WithAudience(launch.Registration.ClientID),
		jwt.WithRequiredClaim("https://purl.imsglobal.org/spec/lti/claim/deployment_id"),
	)
	if err != nil {
		fmt.Printf("failed to verify JWS: %s\n", err)
		return idt, err
	}
	claims := verifiedToken.PrivateClaims()

	// validate that nonce is in the id_token and matches peregrine.Launch nonce
	nonce, ok := claims["nonce"]
	if !ok {
		return idt, fmt.Errorf("nonce missing from id_token")
	}
	if nonce.(string) != launch.Nonce.String() {
		return idt, fmt.Errorf(
			"id_token nonce %s does not match launch nonce %s",
			nonce.(string), launch.Nonce.String(),
		)
	}

	// @TODO - how to handle azp?

	sub, subExist := claims["sub"]
	if subExist && (len(sub.(string)) > 255) {
		return idt, fmt.Errorf("sub %s in id_token exceeds 255 characters", sub.(string))
	}

	// validate deployment_id exists and if launch had deployment_id that it matches
	deploymentId := claims["https://purl.imsglobal.org/spec/lti/claim/deployment_id"].(string)
	if launch.Deployment != nil && deploymentId != launch.Deployment.ID.String() {
		return idt, fmt.Errorf(
			"launch deployment_id %s does not match id_token deployment_id %s",
			launch.Deployment.ID.String(), deploymentId,
		)
	} else {
		_, err := s.dataSvc.GetDeploymentByPlatformDeploymentID(ctx, deploymentId)
		if err != nil {
			return idt, fmt.Errorf(
				"lms deployment_id %s not found in tool lti data source",
				deploymentId,
			)
		}
	}

	// @TODO - get peregrine.PlatformInstance and validate guid against id_token claim
	// @TODO - update launch with peregrine.Deployment ID and peregrine.PlatformInstance ID
	// @TODO - parse LTI claims into response struct

	return idt, nil
}
