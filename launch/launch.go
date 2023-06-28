package launch

import (
	"context"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stevenweathers/peregrine-lti/peregrine"
)

// New returns a new Service for handling LTI launch
func New(config Config, dataSvc peregrine.ToolDataRepo) *Service {
	c := jwk.NewCache(context.Background())

	return &Service{
		config:   config,
		dataSvc:  dataSvc,
		jwkCache: c,
	}
}

// HandleOidcLogin receives the peregrine.OIDCLoginRequestParams
// then validates the request and builds the peregrine.OIDCLoginResponseParams
// to send the Platform in the redirect to peregrine.Platform AuthLoginURL
func (s *Service) HandleOidcLogin() (interface{}, error) {
	return nil, nil
}

// HandleOidcCallback recieves the peregrine.OIDCAuthenticationResponse
// then validates the state and id_token (with claims)
// returning the LTI spec claims omitting oidc claims
func (s *Service) HandleOidcCallback() (interface{}, error) {
	return nil, nil
}
