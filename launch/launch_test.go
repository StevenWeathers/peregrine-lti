package launch

import (
	"context"
	"github.com/google/uuid"
	"github.com/stevenweathers/peregrine-lti/peregrine"
	"testing"
)

type mockStoreSvc struct {
}

// UpsertPlatformInstanceByGUID should create a PlatformInstance if not existing returning PlatformInstance with ID
func (s *mockStoreSvc) UpsertPlatformInstanceByGUID(ctx context.Context, instance peregrine.PlatformInstance) (peregrine.PlatformInstance, error) {
	pi := peregrine.PlatformInstance{}
	return pi, nil
}

// GetRegistrationByClientID should return a Registration by ClientID
func (s *mockStoreSvc) GetRegistrationByClientID(ctx context.Context, clientId string) (peregrine.Registration, error) {
	reg := peregrine.Registration{}
	if clientId == "happypath" {
		reg.ID = uuid.MustParse("7b556115-9460-4f1e-835e-cb11a7301f7d")
		reg.ClientID = clientId
		reg.Platform = &peregrine.Platform{
			ID:           uuid.MustParse("d159b4e7-b790-4f8f-a90b-ae2ce934cfaf"),
			Issuer:       "https://canvas.test.instructure.com",
			KeySetURL:    "https://sso.test.canvaslms.com/api/lti/security/jwks",
			AuthLoginURL: "https://sso.test.canvaslms.com/api/lti/authorize_redirect",
		}
	}
	return reg, nil
}

// UpsertDeploymentByPlatformDeploymentID should create a Deployment if not existing returning a Deployment with ID
func (s *mockStoreSvc) UpsertDeploymentByPlatformDeploymentID(ctx context.Context, deployment peregrine.Deployment) (peregrine.Deployment, error) {
	dep := peregrine.Deployment{}
	return dep, nil
}

// GetLaunch should return a Launch by ID
func (s *mockStoreSvc) GetLaunch(ctx context.Context, id uuid.UUID) (peregrine.Launch, error) {
	l := peregrine.Launch{}
	if id == uuid.MustParse("5daca535-415c-4bfe-8a0e-a7fba8f5d1eb") {

	}
	return l, nil
}

// CreateLaunch should create a Launch returning Launch with ID and Nonce
func (s *mockStoreSvc) CreateLaunch(ctx context.Context, launch peregrine.Launch) (peregrine.Launch, error) {
	l := peregrine.Launch{
		ID:    uuid.MustParse("5daca535-415c-4bfe-8a0e-a7fba8f5d1eb"),
		Nonce: uuid.MustParse("1ff74ccf-8d02-45c0-a881-98f4bf52298f"),
		Registration: &peregrine.Registration{
			ID: uuid.MustParse("7b556115-9460-4f1e-835e-cb11a7301f7d"),
		},
	}
	return l, nil
}

// UpdateLaunch should update a Launch by ID
func (s *mockStoreSvc) UpdateLaunch(ctx context.Context, launch peregrine.Launch) (peregrine.Launch, error) {
	l := peregrine.Launch{}
	return l, nil
}

func TestHandleOidcLoginHappyPath(t *testing.T) {
	launchSvc := New(Config{
		JWTKeySecret: "bringmemoreale!",
		Issuer:       "https://stevenweathers.dev",
	}, &mockStoreSvc{})

	resp, err := launchSvc.HandleOidcLogin(context.Background(), peregrine.OIDCLoginRequestParams{
		Issuer:          "https://canvas.test.instructure.com",
		LoginHint:       "32",
		TargetLinkURI:   "https://stevenweathers.dev",
		ClientID:        "happypath",
		LTIMessageHint:  "",
		LTIDeploymentID: "",
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp.OIDCLoginResponseParams.Scope != "openid" {
		t.Fatalf("OIDCLoginResponseParams.Scope expected openid got %s", resp.OIDCLoginResponseParams.Scope)
	}
	if resp.OIDCLoginResponseParams.ResponseType != "id_token" {
		t.Fatalf("OIDCLoginResponseParams.ResponseType expected id_token got %s", resp.OIDCLoginResponseParams.ResponseType)
	}
	if resp.OIDCLoginResponseParams.ResponseMode != "form_post" {
		t.Fatalf("OIDCLoginResponseParams.ResponseMode expected form_post got %s", resp.OIDCLoginResponseParams.ResponseMode)
	}
	if resp.OIDCLoginResponseParams.Prompt != "none" {
		t.Fatalf("OIDCLoginResponseParams.Prompt expected none got %s", resp.OIDCLoginResponseParams.Prompt)
	}
	if resp.OIDCLoginResponseParams.Nonce == "00000000-0000-0000-0000-000000000000" {
		t.Fatalf("OIDCLoginResponseParams.Nonce to not be default UUID")
	}
	if resp.OIDCLoginResponseParams.LoginHint != "32" {
		t.Fatalf("OIDCLoginResponseParams.LoginHint to be 32")
	}
	if resp.OIDCLoginResponseParams.LTIMessageHint != "" {
		t.Fatalf("OIDCLoginResponseParams.LTIMessageHint to be empty string")
	}

	launchID, err := launchSvc.validateState(resp.OIDCLoginResponseParams.State)
	if err != nil {
		t.Fatal(err)
	}
	expectedLaunchID := uuid.MustParse("5daca535-415c-4bfe-8a0e-a7fba8f5d1eb")
	if launchID != expectedLaunchID {
		t.Fatalf("OIDCLoginResponseParams.State to be generated JTW with launch id of %s got %s", expectedLaunchID, launchID)
	}
}
