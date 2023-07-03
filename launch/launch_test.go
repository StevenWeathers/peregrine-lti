package launch

import (
	"context"
	"encoding/json"
	"fmt"
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

var ltiVersion = "1.3.0"
var ltiClaimMessageType = "LtiResourceLinkRequest"
var canvasTestIssuer = "https://canvas.test.instructure.com"
var canvasTestJWKURL = "/canvaslms/api/lti/security/jwks"
var canvasTestLoginUrl = "/canvaslms/api/lti/authorize_redirect"
var happyPathIssuer = "https://stevenweathers.dev"
var happyPathTargetLinkURI = "https://stevenweathers.dev/"
var happyPathPlatform peregrine.Platform
var happyPathSubClaim = "4cfa2adf-9389-425a-a7d1-436f987cdb11"
var happyPathClientID = "150420000000000007"
var happyPathPlatformInstanceGUID = "someuuidforcanvaslms:canvas-lms"
var happyPathPlatformDeploymentID = "007:9ac4b5c1c2db02e7c70db53837fe8bd47a5e309c"
var happyPathPlatformID = uuid.MustParse("d159b4e7-b790-4f8f-a90b-ae2ce934cfaf")
var happyPathDeploymentID = uuid.MustParse("8024616d-312b-4249-8880-0ecd89e8b909")
var happyPathLaunchID = uuid.MustParse("5daca535-415c-4bfe-8a0e-a7fba8f5d1eb")
var happyPathNonce = uuid.MustParse("1ff74ccf-8d02-45c0-a881-98f4bf52298f")
var happyPathPlatformInstanceID = uuid.MustParse("52166f98-f932-4ccf-ae71-e0ae10255e4f")
var happyPathRegistrationID = uuid.MustParse("7b556115-9460-4f1e-835e-cb11a7301f7d")
var happyPathLaunchWithDeploymentID = uuid.MustParse("65ec0a8c-48e2-423b-b6e0-d1143292d550")
var testStoreSvc *mockStoreSvc

func TestMain(m *testing.M) {
	// Setup a mock JWK keyset and server
	key, _ := jwk.FromRaw([]byte("godofthunder"))
	err := key.Set("kid", "testkey")
	if err != nil {
		panic(err)
	}
	err = key.Set("alg", "HS256")
	if err != nil {
		panic(err)
	}

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
		_, err = w.Write(ks)
		if err != nil {
			panic(err)
		}
	}))

	testStoreSvc = &mockStoreSvc{
		idTokenKey:   key,
		jwkServerURL: srv.URL,
		server:       srv,
	}

	happyPathPlatform = peregrine.Platform{
		ID:           happyPathPlatformID,
		Issuer:       canvasTestIssuer,
		KeySetURL:    srv.URL + canvasTestJWKURL,
		AuthLoginURL: srv.URL + canvasTestLoginUrl,
	}

	exitVal := m.Run()
	srv.Close()
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
		t.Fatalf("expected OIDCLoginResponseParams.Nonce %s to match %s", resp.OIDCLoginResponseParams.Nonce, happyPathNonce.String())
	}
	if resp.OIDCLoginResponseParams.LoginHint != "32" {
		t.Fatalf("expected OIDCLoginResponseParams.LoginHint to be 32")
	}
	if resp.OIDCLoginResponseParams.LTIMessageHint != "" {
		t.Fatalf("expected OIDCLoginResponseParams.LTIMessageHint to be empty string")
	}

	launchID, err := validateState(launchSvc.config.JWTKeySecret, resp.OIDCLoginResponseParams.State)
	if err != nil {
		t.Fatal(err)
	}
	if launchID != happyPathLaunchID {
		t.Fatalf("expected OIDCLoginResponseParams.State to be generated JTW with launch id of %s got %s", happyPathLaunchID, launchID)
	}
}

func TestHandleOidcLoginHappyPathWithLTIMessageHint(t *testing.T) {
	launchSvc := New(Config{
		JWTKeySecret: "bringmemoreale!",
		Issuer:       happyPathIssuer,
	}, testStoreSvc)

	resp, err := launchSvc.HandleOidcLogin(context.Background(), peregrine.OIDCLoginRequestParams{
		Issuer:          canvasTestIssuer,
		LoginHint:       "32",
		TargetLinkURI:   happyPathTargetLinkURI,
		ClientID:        happyPathClientID,
		LTIMessageHint:  "42",
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
		t.Fatalf("expected OIDCLoginResponseParams.Nonce %s to match %s", resp.OIDCLoginResponseParams.Nonce, happyPathNonce.String())
	}
	if resp.OIDCLoginResponseParams.LoginHint != "32" {
		t.Fatalf("expected OIDCLoginResponseParams.LoginHint to be 32")
	}
	if resp.OIDCLoginResponseParams.LTIMessageHint != "42" {
		t.Fatalf("expected OIDCLoginResponseParams.LTIMessageHint to be 42")
	}

	launchID, err := validateState(launchSvc.config.JWTKeySecret, resp.OIDCLoginResponseParams.State)
	if err != nil {
		t.Fatal(err)
	}
	if launchID != happyPathLaunchID {
		t.Fatalf("expected OIDCLoginResponseParams.State to be generated JTW with launch id of %s got %s", happyPathLaunchID, launchID)
	}
}

func TestHandleOidcLoginHappyPathWithDeploymentID(t *testing.T) {
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
		LTIDeploymentID: happyPathPlatformDeploymentID,
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
		t.Fatalf("expected OIDCLoginResponseParams.Nonce %s to match %s", resp.OIDCLoginResponseParams.Nonce, happyPathNonce.String())
	}
	if resp.OIDCLoginResponseParams.LoginHint != "32" {
		t.Fatalf("expected OIDCLoginResponseParams.LoginHint to be 32")
	}
	if resp.OIDCLoginResponseParams.LTIMessageHint != "" {
		t.Fatalf("expected OIDCLoginResponseParams.LTIMessageHint to be empty string")
	}

	launchID, err := validateState(launchSvc.config.JWTKeySecret, resp.OIDCLoginResponseParams.State)
	if err != nil {
		t.Fatal(err)
	}
	if launchID != happyPathLaunchID {
		t.Fatalf("expected OIDCLoginResponseParams.State to be generated JTW with launch id of %s got %s", happyPathLaunchID, launchID)
	}
}

func TestHandleOidcLoginInvalidParams(t *testing.T) {
	launchSvc := New(Config{
		JWTKeySecret: "bringmemoreale!",
		Issuer:       happyPathIssuer,
	}, testStoreSvc)

	_, err := launchSvc.HandleOidcLogin(context.Background(), peregrine.OIDCLoginRequestParams{
		Issuer:          canvasTestIssuer,
		LoginHint:       "32",
		TargetLinkURI:   happyPathTargetLinkURI,
		ClientID:        "",
		LTIMessageHint:  "",
		LTIDeploymentID: "",
	})
	if err.Error() != "failed to validate login request params: MISSING_CLIENT_ID" {
		t.Fatalf("expected invalid params: %v", err)
	}
}

func TestHandleOidcLoginClientIDNotFound(t *testing.T) {
	launchSvc := New(Config{
		JWTKeySecret: "bringmemoreale!",
		Issuer:       happyPathIssuer,
	}, testStoreSvc)

	_, err := launchSvc.HandleOidcLogin(context.Background(), peregrine.OIDCLoginRequestParams{
		Issuer:          canvasTestIssuer,
		LoginHint:       "32",
		TargetLinkURI:   happyPathTargetLinkURI,
		ClientID:        "unknown",
		LTIMessageHint:  "",
		LTIDeploymentID: "",
	})
	if err.Error() != "failed to get registration by client id unknown: REGISTRATION_NOT_FOUND" {
		t.Fatalf("expected invalid params: %v", err)
	}
}

func TestHandleOidcLoginIncorrectIssuer(t *testing.T) {
	launchSvc := New(Config{
		JWTKeySecret: "bringmemoreale!",
		Issuer:       happyPathIssuer,
	}, testStoreSvc)

	_, err := launchSvc.HandleOidcLogin(context.Background(), peregrine.OIDCLoginRequestParams{
		Issuer:          "https://canvas.instructure.com",
		LoginHint:       "32",
		TargetLinkURI:   happyPathTargetLinkURI,
		ClientID:        happyPathClientID,
		LTIMessageHint:  "",
		LTIDeploymentID: "",
	})
	if err.Error() != "request issuer https://canvas.instructure.com does not match registration issuer https://canvas.test.instructure.com" {
		t.Fatalf("expected invalid params: %v", err)
	}
}

func TestHandleOidcCallbackHappyPath(t *testing.T) {
	launchSvc := New(Config{
		JWTKeySecret: "bringmemoreale!",
		Issuer:       happyPathIssuer,
	}, testStoreSvc)

	state, err := createLaunchState(launchSvc.config.Issuer, launchSvc.config.JWTKeySecret, happyPathLaunchID)
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
		Claim("https://purl.imsglobal.org/spec/lti/claim/message_type", ltiClaimMessageType).
		Claim("https://purl.imsglobal.org/spec/lti/claim/version", ltiVersion).
		Claim("https://purl.imsglobal.org/spec/lti/claim/target_link_uri", happyPathTargetLinkURI).
		Claim("https://purl.imsglobal.org/spec/lti/claim/deployment_id", happyPathPlatformDeploymentID).
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

func TestHandleOidcCallbackHappyPathWithLaunchDeploymentID(t *testing.T) {
	launchSvc := New(Config{
		JWTKeySecret: "bringmemoreale!",
		Issuer:       happyPathIssuer,
	}, testStoreSvc)

	state, err := createLaunchState(launchSvc.config.Issuer, launchSvc.config.JWTKeySecret, happyPathLaunchWithDeploymentID)
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
		Claim("https://purl.imsglobal.org/spec/lti/claim/message_type", ltiClaimMessageType).
		Claim("https://purl.imsglobal.org/spec/lti/claim/version", ltiVersion).
		Claim("https://purl.imsglobal.org/spec/lti/claim/target_link_uri", happyPathTargetLinkURI).
		Claim("https://purl.imsglobal.org/spec/lti/claim/deployment_id", happyPathPlatformDeploymentID).
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

func TestHandleOidcCallbackHappyPathWithPlatformInstanceID(t *testing.T) {
	launchSvc := New(Config{
		JWTKeySecret: "bringmemoreale!",
		Issuer:       happyPathIssuer,
	}, testStoreSvc)

	state, err := createLaunchState(launchSvc.config.Issuer, launchSvc.config.JWTKeySecret, happyPathLaunchID)
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
		Claim("https://purl.imsglobal.org/spec/lti/claim/message_type", ltiClaimMessageType).
		Claim("https://purl.imsglobal.org/spec/lti/claim/version", ltiVersion).
		Claim("https://purl.imsglobal.org/spec/lti/claim/target_link_uri", happyPathTargetLinkURI).
		Claim("https://purl.imsglobal.org/spec/lti/claim/deployment_id", happyPathPlatformDeploymentID).
		Claim("https://purl.imsglobal.org/spec/lti/claim/tool_platform", peregrine.PlatformInstanceClaim{
			GUID: happyPathPlatformInstanceGUID,
		}).
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
	instance.ID = happyPathPlatformInstanceID
	return instance, nil
}

// GetRegistrationByClientID should return a Registration by ClientID
func (s *mockStoreSvc) GetRegistrationByClientID(ctx context.Context, clientId string) (peregrine.Registration, error) {
	reg := peregrine.Registration{}
	if clientId == happyPathClientID {
		reg.ID = happyPathRegistrationID
		reg.ClientID = clientId
		reg.Platform = &happyPathPlatform
	} else {
		return reg, fmt.Errorf("REGISTRATION_NOT_FOUND")
	}
	return reg, nil
}

// UpsertDeploymentByPlatformDeploymentID should create a Deployment if not existing returning a Deployment with ID
func (s *mockStoreSvc) UpsertDeploymentByPlatformDeploymentID(ctx context.Context, deployment peregrine.Deployment) (peregrine.Deployment, error) {
	deployment.ID = happyPathDeploymentID
	return deployment, nil
}

// GetLaunch should return a Launch by ID
func (s *mockStoreSvc) GetLaunch(ctx context.Context, id uuid.UUID) (peregrine.Launch, error) {
	l := peregrine.Launch{}
	if id == happyPathLaunchID {
		l.ID = happyPathLaunchID
		l.Nonce = happyPathNonce
		l.Registration = &peregrine.Registration{
			ID:       happyPathRegistrationID,
			ClientID: happyPathClientID,
			Platform: &happyPathPlatform,
		}
	} else if id == happyPathLaunchWithDeploymentID {
		l.ID = happyPathLaunchWithDeploymentID
		l.Nonce = happyPathNonce
		l.Registration = &peregrine.Registration{
			ID:       happyPathRegistrationID,
			ClientID: happyPathClientID,
			Platform: &happyPathPlatform,
		}
		l.Deployment = &peregrine.Deployment{
			ID:                   happyPathDeploymentID,
			PlatformDeploymentID: happyPathPlatformDeploymentID,
		}
	}
	return l, nil
}

// CreateLaunch should create a Launch returning Launch with ID and Nonce
func (s *mockStoreSvc) CreateLaunch(ctx context.Context, launch peregrine.Launch) (peregrine.Launch, error) {
	launch.ID = happyPathLaunchID
	launch.Nonce = happyPathNonce
	return launch, nil
}

// UpdateLaunch should update a Launch by ID
func (s *mockStoreSvc) UpdateLaunch(ctx context.Context, launch peregrine.Launch) (peregrine.Launch, error) {
	return launch, nil
}
