package launch

import (
	"context"
	"fmt"
	"time"

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
		return resp, fmt.Errorf("failed to validate login request params: %v", err)
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

	state, err := createLaunchState(s.config.Issuer, s.config.JWTKeySecret, launch.ID)
	if err != nil {
		return resp, fmt.Errorf("failed to create launch state: %v", err)
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

	launchID, err := validateState(s.config.JWTKeySecret, params.State)
	if err != nil {
		return resp, fmt.Errorf("failed to validate state: %v", err)
	}

	resp.Launch, err = s.dataSvc.GetLaunch(ctx, launchID)
	if err != nil {
		return resp, fmt.Errorf("failed to get launch %s: %v", launchID, err)
	}

	resp.Claims, err = parseIDToken(ctx, s.jwkCache, resp.Launch, params.IDToken)
	if err != nil {
		return resp, fmt.Errorf("failed to parse id_token: %v", err)
	}

	if resp.Claims.DeploymentID != "" && resp.Launch.Deployment == nil {
		deployment, err := s.dataSvc.UpsertDeploymentByPlatformDeploymentID(ctx, peregrine.Deployment{
			Registration: &peregrine.Registration{
				ID: resp.Launch.Registration.ID,
			},
			PlatformDeploymentID: resp.Claims.DeploymentID,
		})
		if err != nil {
			return resp, fmt.Errorf(
				"failed to upsert lms deployment_id %s",
				resp.Claims.DeploymentID,
			)
		}
		resp.Launch.Deployment = &deployment
	}

	// The peregrine.PlatformInstance is purely for audit purposes and not actually meant to be pre-configured by tool
	if resp.Claims.ToolPlatform.GUID != "" {
		platformInstance, err := s.dataSvc.UpsertPlatformInstanceByGUID(ctx, peregrine.PlatformInstance{
			GUID: resp.Claims.ToolPlatform.GUID,
			Platform: &peregrine.Platform{
				ID: resp.Launch.Registration.Platform.ID,
			},
			ContactEmail:      resp.Claims.ToolPlatform.ContactEmail,
			Description:       resp.Claims.ToolPlatform.Description,
			Name:              resp.Claims.ToolPlatform.Name,
			URL:               resp.Claims.ToolPlatform.URL,
			ProductFamilyCode: resp.Claims.ToolPlatform.ProductFamilyCode,
			Version:           resp.Claims.ToolPlatform.Version,
		})
		if err != nil {
			return resp, fmt.Errorf(
				"failed to upsert PlatformInstance by guid %s: %v", resp.Claims.ToolPlatform.GUID, err)
		}
		resp.Launch.PlatformInstance = &platformInstance
	}

	used := time.Now()
	resp.Launch.Used = &used
	_, err = s.dataSvc.UpdateLaunch(ctx, resp.Launch)
	if err != nil {
		return resp, fmt.Errorf("failed to update launch %s: %v", resp.Launch.ID, err)
	}

	return resp, nil
}
