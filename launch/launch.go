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
	HandleOidcLoginResponse, error,
) {
	var deployment *peregrine.Deployment
	resp := HandleOidcLoginResponse{
		OIDCLoginResponseParams: peregrine.OIDCLoginResponseParams{
			Scope:          "openid",
			ResponseType:   "id_token",
			ResponseMode:   "form_post",
			Prompt:         "none",
			ClientID:       params.ClientID,
			LoginHint:      params.LoginHint,
			LTIMessageHint: params.LTIMessageHint,
		},
	}

	err := validateLoginRequestParams(params)
	if err != nil {
		return resp, err
	}

	registration, err := s.dataSvc.GetRegistrationByClientID(ctx, params.ClientID)
	if err != nil {
		return resp, fmt.Errorf("failed to get registration by client id %s: %v", params.ClientID, err)
	}
	resp.RedirectURL = registration.Platform.AuthLoginURL

	if params.Issuer != registration.Platform.Issuer {
		return resp, fmt.Errorf(
			"request issuer %s does not match registration issuer %s",
			params.Issuer, registration.Platform.Issuer,
		)
	}

	if params.LTIDeploymentID != "" {
		dep, err := s.dataSvc.UpsertDeploymentByPlatformDeploymentID(ctx, peregrine.Deployment{
			Registration: &peregrine.Registration{
				ID: registration.ID,
			},
			PlatformDeploymentID: params.LTIDeploymentID,
		})
		if err != nil {
			return resp, fmt.Errorf(
				"failed to upsert deployment %s: %v", params.LTIDeploymentID, err,
			)
		}
		deployment = &dep
	}

	launch, err := s.dataSvc.CreateLaunch(ctx, peregrine.Launch{
		Registration: &registration,
		Deployment:   deployment,
	})
	if err != nil {
		return resp, fmt.Errorf("failed to create launch: %v", err)
	}
	resp.OIDCLoginResponseParams.Nonce = launch.Nonce.String()

	state, err := s.createLaunchState(launch.ID)
	if err != nil {
		return resp, err
	}
	resp.OIDCLoginResponseParams.State = state

	return resp, nil
}

// HandleOidcCallback receives the peregrine.OIDCAuthenticationResponse
// then validates the state and id_token (with claims) as per
// http://www.imsglobal.org/spec/security/v1p0/#authentication-response-validation
// and https://www.imsglobal.org/spec/lti/v1p3#required-message-claims
func (s *Service) HandleOidcCallback(ctx context.Context, params peregrine.OIDCAuthenticationResponse) (
	HandleOidcCallbackResponse, error,
) {
	resp := HandleOidcCallbackResponse{
		Claims: peregrine.LTI1p3Claims{},
		Launch: peregrine.Launch{},
	}

	launchID, err := s.validateState(params.State)
	if err != nil {
		return resp, err
	}

	resp.Launch, err = s.dataSvc.GetLaunch(ctx, launchID)
	if err != nil {
		return resp, fmt.Errorf("failed to get launch %s: %v", launchID, err)
	}

	resp.Claims, err = s.parseIDToken(ctx, resp.Launch, params.IDToken)
	if err != nil {
		return resp, err
	}

	return resp, nil
}
