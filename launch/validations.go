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
		err := s.jwkCache.Register(jwkURL)
		return nil, err
	}
	return s.jwkCache.Refresh(ctx, jwkURL)
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
		fmt.Printf("failed to verify JWS: %s\n", err)
		return launchID, err
	}
	claims := verifiedToken.PrivateClaims()
	lid, ok := claims[launchIDClaim]
	if !ok {
		return launchID, fmt.Errorf("%s claim not found in launch state jwt", launchIDClaim)
	}
	launchID = lid.(uuid.UUID)

	return launchID, nil
}
