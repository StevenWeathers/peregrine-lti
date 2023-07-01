package launch

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stevenweathers/peregrine-lti/peregrine"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

var canvasTestIssuer = "https://canvas.test.instructure.com"
var canvasTestJWKURL = "/canvaslms/api/lti/security/jwks"
var canvasTestLoginUrl = "/canvaslms/api/lti/authorize_redirect"
var happyPathIssuer = "https://stevenweathers.dev"
var happyPathTargetLinkURI = "https://stevenweathers.dev/"
var happyPathPlatform peregrine.Platform
var happyPathSubClaim = "4cfa2adf-9389-425a-a7d1-436f987cdb11"
var happyPathClientID = "150420000000000007"
var happyPathLaunchID = uuid.MustParse("5daca535-415c-4bfe-8a0e-a7fba8f5d1eb")
var happyPathNonce = uuid.MustParse("1ff74ccf-8d02-45c0-a881-98f4bf52298f")
var testStoreSvc *mockStoreSvc

func TestMain(m *testing.M) {
	// Setup a mock JWK keyset and server
	key, _ := jwk.FromRaw([]byte("godofthunder"))
	key.Set("kid", "testkey")
	key.Set("alg", "HS256")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		type response struct {
			Keys []jwk.Key `json:"keys"`
		}
		keys := make([]jwk.Key, 0)

		k, err := key.PublicKey()
		if err != nil {
			panic(err)
		}
		keys = append(keys, k)
		resp := response{
			Keys: keys,
		}
		ks, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.Write(ks)
	}))

	testStoreSvc = &mockStoreSvc{
		idTokenKey:   key,
		jwkServerURL: srv.URL,
		server:       srv,
	}

	happyPathPlatform = peregrine.Platform{
		ID:           uuid.MustParse("d159b4e7-b790-4f8f-a90b-ae2ce934cfaf"),
		Issuer:       canvasTestIssuer,
		KeySetURL:    srv.URL + canvasTestJWKURL,
		AuthLoginURL: srv.URL + canvasTestLoginUrl,
	}

	exitVal := m.Run()
	os.Exit(exitVal)
}

func TestHandleOidcLoginHappyPath(t *testing.T) {
	launchSvc := New(Config{
		JWTKeySecret: "bringmemoreale!",
		Issuer:       happyPathIssuer,
	}, testStoreSvc)

	resp, err := launchSvc.HandleOidcLogin(context.Background(), peregrine.OIDCLoginRequestParams{
		Issuer:          canvasTestIssuer,
		LoginHint:       "32",
		TargetLinkURI:   happyPathTargetLinkURI,
		ClientID:        happyPathClientID,
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
	if resp.OIDCLoginResponseParams.Nonce != happyPathNonce.String() {
		t.Fatalf("OIDCLoginResponseParams.Nonce %s to match %s", resp.OIDCLoginResponseParams.Nonce, happyPathNonce.String())
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

func TestHandleOidcCallbackHappyPath(t *testing.T) {
	launchSvc := New(Config{
		JWTKeySecret: "bringmemoreale!",
		Issuer:       happyPathIssuer,
	}, testStoreSvc)

	expectedLaunchID := uuid.MustParse("5daca535-415c-4bfe-8a0e-a7fba8f5d1eb")
	state, err := launchSvc.createLaunchState(expectedLaunchID)
	if err != nil {
		t.Fatal(err)
	}

	// Create a mock id_token
	tok, err := jwt.NewBuilder().
		Issuer(canvasTestIssuer).
		IssuedAt(time.Now()).
		Audience([]string{happyPathClientID}).
		Subject(happyPathSubClaim).
		Expiration(time.Now().Add(time.Minute*10)).
		Claim("nonce", happyPathNonce.String()).
		Claim(
			"https://purl.imsglobal.org/spec/lti/claim/deployment_id",
			"007:9ac4b5c1c2db02e7c70db53837fe8bd47a5e309c",
		).
		Claim("https://purl.imsglobal.org/spec/lti/claim/message_type", "LtiResourceLinkRequest").
		Claim("https://purl.imsglobal.org/spec/lti/claim/version", "1.3.0").
		Claim("https://purl.imsglobal.org/spec/lti/claim/target_link_uri", happyPathTargetLinkURI).
		Build()
	if err != nil {
		panic(err)
	}
	signedIdToken, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256, testStoreSvc.idTokenKey))
	if err != nil {
		panic(err)
	}

	res, err := launchSvc.HandleOidcCallback(context.Background(), peregrine.OIDCAuthenticationResponse{
		State:   state,
		IDToken: string(signedIdToken),
	})
	if err != nil {
		t.Fatal(err)
	}

	if res.Launch.Used == nil {
		t.Fatal("expected Launch.Used to not be nil")
	}
}

// -- MOCKS --
type mockStoreSvc struct {
	idTokenKey   jwk.Key
	jwkServerURL string
	server       *httptest.Server
}

// UpsertPlatformInstanceByGUID should create a PlatformInstance if not existing returning PlatformInstance with ID
func (s *mockStoreSvc) UpsertPlatformInstanceByGUID(ctx context.Context, instance peregrine.PlatformInstance) (peregrine.PlatformInstance, error) {
	pi := peregrine.PlatformInstance{}
	return pi, nil
}

// GetRegistrationByClientID should return a Registration by ClientID
func (s *mockStoreSvc) GetRegistrationByClientID(ctx context.Context, clientId string) (peregrine.Registration, error) {
	reg := peregrine.Registration{}
	if clientId == happyPathClientID {
		reg.ID = uuid.MustParse("7b556115-9460-4f1e-835e-cb11a7301f7d")
		reg.ClientID = clientId
		reg.Platform = &happyPathPlatform
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
	if id == happyPathLaunchID {
		l.ID = happyPathLaunchID
		l.Nonce = happyPathNonce
		l.Registration = &peregrine.Registration{
			ID:       uuid.MustParse("7b556115-9460-4f1e-835e-cb11a7301f7d"),
			ClientID: happyPathClientID,
			Platform: &happyPathPlatform,
		}
	}
	return l, nil
}

// CreateLaunch should create a Launch returning Launch with ID and Nonce
func (s *mockStoreSvc) CreateLaunch(ctx context.Context, launch peregrine.Launch) (peregrine.Launch, error) {
	l := peregrine.Launch{
		ID:           happyPathLaunchID,
		Nonce:        happyPathNonce,
		Registration: launch.Registration,
	}
	return l, nil
}

// UpdateLaunch should update a Launch by ID
func (s *mockStoreSvc) UpdateLaunch(ctx context.Context, launch peregrine.Launch) (peregrine.Launch, error) {
	return launch, nil
}
