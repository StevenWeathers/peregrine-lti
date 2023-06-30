package launch

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/stevenweathers/peregrine-lti/peregrine"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

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

func (s *Service) BuildLoginResponseRedirectURL(
	response peregrine.OIDCLoginResponseParams, platformAuthLoginUrl, callbackUrl string,
) (string, error) {
	var redirURL string

	redirReq, err := url.Parse(platformAuthLoginUrl)
	if err != nil {
		return redirURL, fmt.Errorf("failed to build OIDC login response redirect URL: %v", err)
	}

	q := redirReq.Query()
	q.Add("scope", response.Scope)
	q.Add("response_type", response.ResponseType)
	q.Add("response_mode", response.ResponseMode)
	q.Add("prompt", response.Prompt)
	q.Add("client_id", response.ClientID)
	q.Add("redirect_uri", callbackUrl)
	q.Add("state", response.State)
	q.Add("nonce", response.Nonce)
	q.Add("login_hint", response.LoginHint)
	if response.LTIMessageHint != "" {
		q.Add("lti_message_hint", response.LTIMessageHint)
	}

	redirReq.RawQuery = q.Encode()
	redirURL = redirReq.String()

	return redirURL, nil
}
