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
func (s *Service) HandleOidcLogin(params peregrine.OIDCLoginRequestParams) (peregrine.OIDCLoginResponseParams, error) {
	resp := peregrine.OIDCLoginResponseParams{}

	return resp, nil
}

// HandleOidcCallback receives the peregrine.OIDCAuthenticationResponse
// then validates the state and id_token (with claims) as per
// http://www.imsglobal.org/spec/security/v1p0/#authentication-response-validation
// and https://www.imsglobal.org/spec/lti/v1p3#required-message-claims
// returning the LTI spec claims omitting oidc claims
func (s *Service) HandleOidcCallback(params peregrine.OIDCAuthenticationResponse) (peregrine.LTI1p3Claims, error) {
	res := peregrine.LTI1p3Claims{}

	return res, nil
}
