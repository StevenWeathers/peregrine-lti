package launch

import (
	"context"
	"fmt"

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
func (s *Service) HandleOidcLogin(ctx context.Context, params peregrine.OIDCLoginRequestParams) (
	response peregrine.OIDCLoginResponseParams, redirectUrl string, error error,
) {
	var deployment *peregrine.Deployment
	var redir string
	resp := peregrine.OIDCLoginResponseParams{
		Scope:          "openid",
		ResponseType:   "id_token",
		ResponseMode:   "form_post",
		Prompt:         "none",
		ClientID:       params.ClientID,
		LoginHint:      params.LoginHint,
		LTIMessageHint: params.LTIMessageHint,
	}

	err := validateLoginRequestParams(params)
	if err != nil {
		return resp, redir, err
	}

	registration, err := s.dataSvc.GetRegistrationByClientID(ctx, params.ClientID)
	if err != nil {
		return resp, redir, err
	}
	redir = registration.Platform.AuthLoginURL

	if params.Issuer != registration.Platform.Issuer {
		return resp, redir, fmt.Errorf(
			"request issuer %s does not match registration issuer %s",
			params.Issuer, registration.Platform.Issuer,
		)
	}

	if params.LTIDeploymentID != "" {
		dep, err := s.dataSvc.GetDeploymentByPlatformDeploymentID(ctx, params.LTIDeploymentID)
		if err != nil {
			return resp, redir, fmt.Errorf(
				"lms deployment_id %s not found in tool lti data source",
				params.LTIDeploymentID,
			)
		}
		deployment = &dep
	}

	launch, err := s.dataSvc.CreateLaunch(ctx, peregrine.Launch{
		Registration: &registration,
		Deployment:   deployment,
	})
	if err != nil {
		return resp, redir, err
	}
	resp.Nonce = launch.Nonce.String()

	state, err := s.createLaunchState(launch.ID)
	if err != nil {
		return resp, redir, err
	}
	resp.State = state

	return resp, redir, nil
}

// HandleOidcCallback receives the peregrine.OIDCAuthenticationResponse
// then validates the state and id_token (with claims) as per
// http://www.imsglobal.org/spec/security/v1p0/#authentication-response-validation
// and https://www.imsglobal.org/spec/lti/v1p3#required-message-claims
// returning the LTI spec claims omitting oidc claims and the peregrine.Launch
func (s *Service) HandleOidcCallback(ctx context.Context, params peregrine.OIDCAuthenticationResponse) (
	peregrine.LTI1p3Claims, peregrine.Launch, error,
) {
	launch := peregrine.Launch{}
	resp := peregrine.LTI1p3Claims{}

	launchID, err := s.validateState(params.State)
	if err != nil {
		return resp, launch, err
	}

	launch, err = s.dataSvc.GetLaunch(ctx, launchID)
	if err != nil {
		return resp, launch, err
	}

	claims, err := s.parseIDToken(ctx, launch, params.IDToken)
	if err != nil {
		return resp, launch, err
	}

	resp = claims

	return resp, launch, nil
}
