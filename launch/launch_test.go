package launch

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stevenweathers/peregrine-lti/peregrine"
)

const (
	toolPlatformClaim        = "https://purl.imsglobal.org/spec/lti/claim/tool_platform"
	canvasTestIssuer         = "https://canvas.test.instructure.com"
	canvasTestJWKURL         = "/canvaslms/api/lti/security/jwks"
	canvasTestLoginUrl       = "/canvaslms/api/lti/authorize_redirect"
	testIssuer               = "https://stevenweathers.dev"
	testTargetLinkURI        = "https://stevenweathers.dev/"
	testSubClaim             = "4cfa2adf-9389-425a-a7d1-436f987cdb11"
	testClientID             = "150420000000000007"
	testPlatformInstanceGUID = "someuuidforcanvaslms:canvas-lms"
	testPlatformDeploymentID = "007:9ac4b5c1c2db02e7c70db53837fe8bd47a5e309c"
	testJWTSecret            = "godofthunder"
)

var (
	happyPathPlatform          peregrine.Platform
	testPlatformID             = uuid.MustParse("d159b4e7-b790-4f8f-a90b-ae2ce934cfaf")
	testDeploymentID           = uuid.MustParse("8024616d-312b-4249-8880-0ecd89e8b909")
	testLaunchID               = uuid.MustParse("5daca535-415c-4bfe-8a0e-a7fba8f5d1eb")
	testNonce                  = uuid.MustParse("1ff74ccf-8d02-45c0-a881-98f4bf52298f")
	testPlatformInstanceID     = uuid.MustParse("52166f98-f932-4ccf-ae71-e0ae10255e4f")
	testRegistrationID         = uuid.MustParse("7b556115-9460-4f1e-835e-cb11a7301f7d")
	testLaunchWithDeploymentID = uuid.MustParse("65ec0a8c-48e2-423b-b6e0-d1143292d550")
	testJwkKey                 jwk.Key
	testSrvUrl                 string
)

func TestMain(m *testing.M) {
	// Setup a mock JWK keyset and server
	key, _ := jwk.FromRaw([]byte(testJWTSecret))
	err := key.Set(jwk.KeyIDKey, "testkey")
	if err != nil {
		panic(err)
	}
	err = key.Set(jwk.AlgorithmKey, "HS256")
	if err != nil {
		panic(err)
	}
	keys := make([]jwk.Key, 0)

	k, err := key.PublicKey()
	if err != nil {
		panic(err)
	}
	keys = append(keys, k)
	type jwkResponse struct {
		Keys []jwk.Key `json:"keys"`
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != canvasTestJWKURL {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		resp := jwkResponse{
			Keys: keys,
		}
		ks, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, err = w.Write(ks)
		if err != nil {
			panic(err)
		}
	}))
	defer srv.Close()

	testJwkKey = key
	testSrvUrl = srv.URL
	happyPathPlatform = peregrine.Platform{
		ID:           testPlatformID,
		Issuer:       canvasTestIssuer,
		KeySetURL:    srv.URL + canvasTestJWKURL,
		AuthLoginURL: srv.URL + canvasTestLoginUrl,
	}

	exitVal := m.Run()
	srv.Close()
	os.Exit(exitVal)
}

func TestHandleOidcLoginHappyPath(t *testing.T) {
	t.Parallel()
	launchSvc := New(Config{
		JWTKeySecret: testJWTSecret,
		Issuer:       testIssuer,
	}, &mockStoreSvc{})

	resp, err := launchSvc.HandleOidcLogin(context.Background(), peregrine.OIDCLoginRequestParams{
		Issuer:          canvasTestIssuer,
		LoginHint:       "32",
		TargetLinkURI:   testTargetLinkURI,
		ClientID:        testClientID,
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
	if resp.OIDCLoginResponseParams.Nonce != testNonce.String() {
		t.Fatalf("expected OIDCLoginResponseParams.Nonce %s to match %s", resp.OIDCLoginResponseParams.Nonce, testNonce.String())
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
	if launchID != testLaunchID {
		t.Fatalf("expected OIDCLoginResponseParams.State to be generated JTW with launch id of %s got %s", testLaunchID, launchID)
	}
}

func TestHandleOidcLoginHappyPathWithLTIMessageHint(t *testing.T) {
	t.Parallel()
	launchSvc := New(Config{
		JWTKeySecret: testJWTSecret,
		Issuer:       testIssuer,
	}, &mockStoreSvc{})

	resp, err := launchSvc.HandleOidcLogin(context.Background(), peregrine.OIDCLoginRequestParams{
		Issuer:          canvasTestIssuer,
		LoginHint:       "32",
		TargetLinkURI:   testTargetLinkURI,
		ClientID:        testClientID,
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
	if resp.OIDCLoginResponseParams.Nonce != testNonce.String() {
		t.Fatalf("expected OIDCLoginResponseParams.Nonce %s to match %s", resp.OIDCLoginResponseParams.Nonce, testNonce.String())
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
	if launchID != testLaunchID {
		t.Fatalf("expected OIDCLoginResponseParams.State to be generated JTW with launch id of %s got %s", testLaunchID, launchID)
	}
}

func TestHandleOidcLoginHappyPathWithDeploymentID(t *testing.T) {
	t.Parallel()
	launchSvc := New(Config{
		JWTKeySecret: testJWTSecret,
		Issuer:       testIssuer,
	}, &mockStoreSvc{})

	resp, err := launchSvc.HandleOidcLogin(context.Background(), peregrine.OIDCLoginRequestParams{
		Issuer:          canvasTestIssuer,
		LoginHint:       "32",
		TargetLinkURI:   testTargetLinkURI,
		ClientID:        testClientID,
		LTIMessageHint:  "",
		LTIDeploymentID: testPlatformDeploymentID,
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
	if resp.OIDCLoginResponseParams.Nonce != testNonce.String() {
		t.Fatalf("expected OIDCLoginResponseParams.Nonce %s to match %s", resp.OIDCLoginResponseParams.Nonce, testNonce.String())
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
	if launchID != testLaunchID {
		t.Fatalf("expected OIDCLoginResponseParams.State to be generated JTW with launch id of %s got %s", testLaunchID, launchID)
	}
}

func TestHandleOidcLoginInvalidParams(t *testing.T) {
	t.Parallel()
	launchSvc := New(Config{
		JWTKeySecret: testJWTSecret,
		Issuer:       testIssuer,
	}, &mockStoreSvc{})

	_, err := launchSvc.HandleOidcLogin(context.Background(), peregrine.OIDCLoginRequestParams{
		Issuer:          canvasTestIssuer,
		LoginHint:       "32",
		TargetLinkURI:   testTargetLinkURI,
		ClientID:        "",
		LTIMessageHint:  "",
		LTIDeploymentID: "",
	})
	if err.Error() != "failed to validate login request params: MISSING_CLIENT_ID" {
		t.Fatalf("expected invalid params: %v", err)
	}
}

func TestHandleOidcLoginClientIDNotFound(t *testing.T) {
	t.Parallel()
	launchSvc := New(Config{
		JWTKeySecret: testJWTSecret,
		Issuer:       testIssuer,
	}, &mockStoreSvcWithRegistrationNotFound{})

	_, err := launchSvc.HandleOidcLogin(context.Background(), peregrine.OIDCLoginRequestParams{
		Issuer:          canvasTestIssuer,
		LoginHint:       "32",
		TargetLinkURI:   testTargetLinkURI,
		ClientID:        testClientID,
		LTIMessageHint:  "",
		LTIDeploymentID: "",
	})
	if err.Error() != fmt.Sprintf("failed to get registration by client id %s: REGISTRATION_NOT_FOUND", testClientID) {
		t.Fatalf("expected invalid params: %v", err)
	}
}

func TestHandleOidcLoginIncorrectIssuer(t *testing.T) {
	t.Parallel()
	launchSvc := New(Config{
		JWTKeySecret: testJWTSecret,
		Issuer:       testIssuer,
	}, &mockStoreSvc{})

	_, err := launchSvc.HandleOidcLogin(context.Background(), peregrine.OIDCLoginRequestParams{
		Issuer:          "https://canvas.instructure.com",
		LoginHint:       "32",
		TargetLinkURI:   testTargetLinkURI,
		ClientID:        testClientID,
		LTIMessageHint:  "",
		LTIDeploymentID: "",
	})
	if err.Error() != fmt.Sprintf("request issuer https://canvas.instructure.com does not match registration issuer %s", canvasTestIssuer) {
		t.Fatalf("expected invalid params: %v", err)
	}
}

func TestHandleOidcLoginUpsertDeploymentFailure(t *testing.T) {
	t.Parallel()
	launchSvc := New(Config{
		JWTKeySecret: testJWTSecret,
		Issuer:       testIssuer,
	}, &mockStoreSvcWithFailedDeploymentUpsert{})

	_, err := launchSvc.HandleOidcLogin(context.Background(), peregrine.OIDCLoginRequestParams{
		Issuer:          canvasTestIssuer,
		LoginHint:       "32",
		TargetLinkURI:   testTargetLinkURI,
		ClientID:        testClientID,
		LTIMessageHint:  "",
		LTIDeploymentID: testDeploymentID.String(),
	})
	if err.Error() != "failed to upsert deployment 8024616d-312b-4249-8880-0ecd89e8b909: upsert deployment forced failure" {
		t.Fatalf("expected upsert deployment failure: %v", err)
	}
}

func TestHandleOidcLoginCreateLaunchFailure(t *testing.T) {
	t.Parallel()
	launchSvc := New(Config{
		JWTKeySecret: testJWTSecret,
		Issuer:       testIssuer,
	}, &mockStoreSvcWithFailedLaunchCreate{})

	_, err := launchSvc.HandleOidcLogin(context.Background(), peregrine.OIDCLoginRequestParams{
		Issuer:          canvasTestIssuer,
		LoginHint:       "32",
		TargetLinkURI:   testTargetLinkURI,
		ClientID:        testClientID,
		LTIMessageHint:  "",
		LTIDeploymentID: testDeploymentID.String(),
	})
	if err.Error() != "failed to create launch: test create launch failed" {
		t.Fatalf("expected launch create failure: %v", err)
	}
}

func TestHandleOidcCallbackHappyPath(t *testing.T) {
	t.Parallel()
	launchSvc := New(Config{
		JWTKeySecret: testJWTSecret,
		Issuer:       testIssuer,
	}, &mockStoreSvc{})

	state, err := createLaunchState(launchSvc.config.Issuer, launchSvc.config.JWTKeySecret, testLaunchID)
	if err != nil {
		t.Fatal(err)
	}

	// Create a mock id_token
	tok, err := jwt.NewBuilder().
		Issuer(canvasTestIssuer).
		IssuedAt(time.Now()).
		Audience([]string{testClientID}).
		Subject(testSubClaim).
		Expiration(time.Now().Add(time.Minute*10)).
		Claim(nonceClaim, testNonce.String()).
		Claim(ltiMessageTypeClaim, ltiMessageTypeClaimValue).
		Claim(ltiVersionClaim, ltiVersionClaimValue).
		Claim(ltiTargetLinkUriClaim, testTargetLinkURI).
		Claim(ltiDeploymentIdClaim, testPlatformDeploymentID).
		Build()
	if err != nil {
		panic(err)
	}
	signedIdToken, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256, testJwkKey))
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
	t.Parallel()
	launchSvc := New(Config{
		JWTKeySecret: testJWTSecret,
		Issuer:       testIssuer,
	}, &mockStoreSvc{})

	state, err := createLaunchState(launchSvc.config.Issuer, launchSvc.config.JWTKeySecret, testLaunchWithDeploymentID)
	if err != nil {
		t.Fatal(err)
	}

	// Create a mock id_token
	tok, err := jwt.NewBuilder().
		Issuer(canvasTestIssuer).
		IssuedAt(time.Now()).
		Audience([]string{testClientID}).
		Subject(testSubClaim).
		Expiration(time.Now().Add(time.Minute*10)).
		Claim(nonceClaim, testNonce.String()).
		Claim(ltiMessageTypeClaim, ltiMessageTypeClaimValue).
		Claim(ltiVersionClaim, ltiVersionClaimValue).
		Claim(ltiTargetLinkUriClaim, testTargetLinkURI).
		Claim(ltiDeploymentIdClaim, testPlatformDeploymentID).
		Build()
	if err != nil {
		panic(err)
	}
	signedIdToken, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256, testJwkKey))
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
	t.Parallel()
	launchSvc := New(Config{
		JWTKeySecret: testJWTSecret,
		Issuer:       testIssuer,
	}, &mockStoreSvc{})

	state, err := createLaunchState(launchSvc.config.Issuer, launchSvc.config.JWTKeySecret, testLaunchID)
	if err != nil {
		t.Fatal(err)
	}

	// Create a mock id_token
	tok, err := jwt.NewBuilder().
		Issuer(canvasTestIssuer).
		IssuedAt(time.Now()).
		Audience([]string{testClientID}).
		Subject(testSubClaim).
		Expiration(time.Now().Add(time.Minute*10)).
		Claim(nonceClaim, testNonce.String()).
		Claim(ltiMessageTypeClaim, ltiMessageTypeClaimValue).
		Claim(ltiVersionClaim, ltiVersionClaimValue).
		Claim(ltiTargetLinkUriClaim, testTargetLinkURI).
		Claim(ltiDeploymentIdClaim, testPlatformDeploymentID).
		Claim(toolPlatformClaim, peregrine.PlatformInstanceClaim{
			GUID: testPlatformInstanceGUID,
		}).
		Build()
	if err != nil {
		panic(err)
	}
	signedIdToken, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256, testJwkKey))
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

func TestHandleOidcCallbackInvalidState(t *testing.T) {
	t.Parallel()
	launchSvc := New(Config{
		JWTKeySecret: testJWTSecret,
		Issuer:       testIssuer,
	}, &mockStoreSvc{})

	_, err := launchSvc.HandleOidcCallback(context.Background(), peregrine.OIDCAuthenticationResponse{
		State:   "",
		IDToken: "",
	})
	if err == nil || !strings.Contains(err.Error(), "failed to validate state:") {
		t.Fatalf("expected error %v", err)
	}
}

func TestHandleOidcCallbackInvalidIDToken(t *testing.T) {
	t.Parallel()
	launchSvc := New(Config{
		JWTKeySecret: testJWTSecret,
		Issuer:       testIssuer,
	}, &mockStoreSvc{})

	state, err := createLaunchState(launchSvc.config.Issuer, launchSvc.config.JWTKeySecret, testLaunchID)
	if err != nil {
		t.Fatal(err)
	}

	_, err = launchSvc.HandleOidcCallback(context.Background(), peregrine.OIDCAuthenticationResponse{
		State:   state,
		IDToken: "",
	})
	if err == nil || !strings.Contains(err.Error(), "invalid id_token:") {
		t.Fatalf("expected error %v", err)
	}
}

func TestHandleOidcCallbackLaunchIDNotFound(t *testing.T) {
	t.Parallel()
	launchSvc := New(Config{
		JWTKeySecret: testJWTSecret,
		Issuer:       testIssuer,
	}, &mockStoreSvc{})

	state, err := createLaunchState(launchSvc.config.Issuer, launchSvc.config.JWTKeySecret, testDeploymentID)
	if err != nil {
		t.Fatal(err)
	}

	// Create a mock id_token
	tok, err := jwt.NewBuilder().
		Issuer(canvasTestIssuer).
		IssuedAt(time.Now()).
		Audience([]string{testClientID}).
		Subject(testSubClaim).
		Expiration(time.Now().Add(time.Minute*10)).
		Claim(nonceClaim, testNonce.String()).
		Claim(ltiMessageTypeClaim, ltiMessageTypeClaimValue).
		Claim(ltiVersionClaim, ltiVersionClaimValue).
		Claim(ltiTargetLinkUriClaim, testTargetLinkURI).
		Claim(ltiDeploymentIdClaim, testPlatformDeploymentID).
		Build()
	if err != nil {
		panic(err)
	}
	signedIdToken, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256, testJwkKey))
	if err != nil {
		panic(err)
	}

	_, err = launchSvc.HandleOidcCallback(context.Background(), peregrine.OIDCAuthenticationResponse{
		State:   state,
		IDToken: string(signedIdToken),
	})
	if err == nil || !strings.Contains(err.Error(), "failed to get launch 8024616d-312b-4249-8880-0ecd89e8b909: LAUNCH_NOT_FOUND") {
		t.Fatalf("expected error: %v", err)
	}
}

func TestHandleOidcCallbackDeploymentUpsertFailure(t *testing.T) {
	t.Parallel()

	launchSvc := New(Config{
		JWTKeySecret: testJWTSecret,
		Issuer:       testIssuer,
	}, &mockStoreSvcWithFailedDeploymentUpsert{})

	state, err := createLaunchState(launchSvc.config.Issuer, launchSvc.config.JWTKeySecret, testLaunchID)
	if err != nil {
		t.Fatal(err)
	}

	// Create a mock id_token
	tok, err := jwt.NewBuilder().
		Issuer(canvasTestIssuer).
		IssuedAt(time.Now()).
		Audience([]string{testClientID}).
		Subject(testSubClaim).
		Expiration(time.Now().Add(time.Minute*10)).
		Claim(nonceClaim, testNonce.String()).
		Claim(ltiMessageTypeClaim, ltiMessageTypeClaimValue).
		Claim(ltiVersionClaim, ltiVersionClaimValue).
		Claim(ltiTargetLinkUriClaim, testTargetLinkURI).
		Claim(ltiDeploymentIdClaim, testPlatformDeploymentID).
		Build()
	if err != nil {
		panic(err)
	}
	signedIdToken, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256, testJwkKey))
	if err != nil {
		panic(err)
	}

	_, err = launchSvc.HandleOidcCallback(context.Background(), peregrine.OIDCAuthenticationResponse{
		State:   state,
		IDToken: string(signedIdToken),
	})
	if err == nil || !strings.Contains(err.Error(), "failed to upsert lms deployment_id") {
		t.Fatalf("expected error: %v", err)
	}
}

func TestHandleOidcCallbackWithUpdateLaunchFailure(t *testing.T) {
	t.Parallel()
	launchSvc := New(Config{
		JWTKeySecret: testJWTSecret,
		Issuer:       testIssuer,
	}, &mockStoreSvcWithFailedLaunchUpdate{})

	state, err := createLaunchState(launchSvc.config.Issuer, launchSvc.config.JWTKeySecret, testLaunchID)
	if err != nil {
		t.Fatal(err)
	}

	// Create a mock id_token
	tok, err := jwt.NewBuilder().
		Issuer(canvasTestIssuer).
		IssuedAt(time.Now()).
		Audience([]string{testClientID}).
		Subject(testSubClaim).
		Expiration(time.Now().Add(time.Minute*10)).
		Claim(nonceClaim, testNonce.String()).
		Claim(ltiMessageTypeClaim, ltiMessageTypeClaimValue).
		Claim(ltiVersionClaim, ltiVersionClaimValue).
		Claim(ltiTargetLinkUriClaim, testTargetLinkURI).
		Claim(ltiDeploymentIdClaim, testPlatformDeploymentID).
		Build()
	if err != nil {
		panic(err)
	}
	signedIdToken, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256, testJwkKey))
	if err != nil {
		panic(err)
	}

	_, err = launchSvc.HandleOidcCallback(context.Background(), peregrine.OIDCAuthenticationResponse{
		State:   state,
		IDToken: string(signedIdToken),
	})

	if err == nil || !strings.Contains(err.Error(), "update launch forced failure") {
		t.Fatalf("expected error: %v", err)
	}
}

func TestHandleOidcCallbackWithUpsertPlatformInstanceFailure(t *testing.T) {
	t.Parallel()
	launchSvc := New(Config{
		JWTKeySecret: testJWTSecret,
		Issuer:       testIssuer,
	}, &mockStoreSvcWithFailedPlatformInstanceUpsert{})

	state, err := createLaunchState(launchSvc.config.Issuer, launchSvc.config.JWTKeySecret, testLaunchID)
	if err != nil {
		t.Fatal(err)
	}

	// Create a mock id_token
	tok, err := jwt.NewBuilder().
		Issuer(canvasTestIssuer).
		IssuedAt(time.Now()).
		Audience([]string{testClientID}).
		Subject(testSubClaim).
		Expiration(time.Now().Add(time.Minute*10)).
		Claim(nonceClaim, testNonce.String()).
		Claim(ltiMessageTypeClaim, ltiMessageTypeClaimValue).
		Claim(ltiVersionClaim, ltiVersionClaimValue).
		Claim(ltiTargetLinkUriClaim, testTargetLinkURI).
		Claim(ltiDeploymentIdClaim, testPlatformDeploymentID).
		Claim(toolPlatformClaim, peregrine.PlatformInstanceClaim{
			GUID: testPlatformInstanceGUID,
		}).
		Build()
	if err != nil {
		panic(err)
	}
	signedIdToken, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256, testJwkKey))
	if err != nil {
		panic(err)
	}

	_, err = launchSvc.HandleOidcCallback(context.Background(), peregrine.OIDCAuthenticationResponse{
		State:   state,
		IDToken: string(signedIdToken),
	})

	if err == nil || !strings.Contains(err.Error(), "upsert platform instance forced failure") {
		t.Fatalf("expected error: %v", err)
	}
}

func TestHandleOidcCallbackInvalidSubjectClaim(t *testing.T) {
	t.Parallel()
	launchSvc := New(Config{
		JWTKeySecret: testJWTSecret,
		Issuer:       testIssuer,
	}, &mockStoreSvc{})

	state, err := createLaunchState(launchSvc.config.Issuer, launchSvc.config.JWTKeySecret, testLaunchID)
	if err != nil {
		t.Fatal(err)
	}

	tooLongSub := "7SjE7orkCPiIyad9miJuOFEHoL5TUppLnVE6qbtJgS0FzoQxDa3G86lOMczmb6rfIkcnkukdC3R1xYXcI353k9WsVdZfyUohVxFaLbrdarvbex1YwQ0lTiHirx1gP82eYC1rspJoHOfHXU2Wa9UI47MPEUTTgkQOCBiakOh5B43amp7pmw5FdbsY1rJxs2xQbGMnAZ12rR2qMPqufT0JM1FFMYmqieC8TTRtX4XlXt0QsOSPFyLJ94VeZDgg2q2C"

	// Create a mock id_token
	tok, err := jwt.NewBuilder().
		Issuer(canvasTestIssuer).
		IssuedAt(time.Now()).
		Audience([]string{testClientID}).
		Subject(tooLongSub).
		Expiration(time.Now().Add(time.Minute*10)).
		Claim(nonceClaim, testNonce.String()).
		Claim(ltiMessageTypeClaim, ltiMessageTypeClaimValue).
		Claim(ltiVersionClaim, ltiVersionClaimValue).
		Claim(ltiTargetLinkUriClaim, testTargetLinkURI).
		Claim(ltiDeploymentIdClaim, testPlatformDeploymentID).
		Build()
	if err != nil {
		panic(err)
	}
	signedIdToken, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256, testJwkKey))
	if err != nil {
		panic(err)
	}

	_, err = launchSvc.HandleOidcCallback(context.Background(), peregrine.OIDCAuthenticationResponse{
		State:   state,
		IDToken: string(signedIdToken),
	})
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("sub %s in id_token exceeds 255 characters", tooLongSub)) {
		t.Fatalf("expected error: %v", err)
	}
}

// mockStoreSvc mocks the data store service dependency
type mockStoreSvc struct{}

// UpsertPlatformInstanceByGUID should create a PlatformInstance if not existing returning PlatformInstance with ID
func (s *mockStoreSvc) UpsertPlatformInstanceByGUID(ctx context.Context, instance peregrine.PlatformInstance) (peregrine.PlatformInstance, error) {
	instance.ID = testPlatformInstanceID
	return instance, nil
}

// GetRegistrationByClientID should return a Registration by ClientID
func (s *mockStoreSvc) GetRegistrationByClientID(ctx context.Context, clientId string) (peregrine.Registration, error) {
	reg := peregrine.Registration{}
	if clientId == testClientID {
		reg.ID = testRegistrationID
		reg.ClientID = clientId
		reg.Platform = &happyPathPlatform
	} else {
		return reg, fmt.Errorf("REGISTRATION_NOT_FOUND")
	}
	return reg, nil
}

// UpsertDeploymentByPlatformDeploymentID should create a Deployment if not existing returning a Deployment with ID
func (s *mockStoreSvc) UpsertDeploymentByPlatformDeploymentID(ctx context.Context, deployment peregrine.Deployment) (peregrine.Deployment, error) {
	deployment.ID = testDeploymentID
	return deployment, nil
}

// GetLaunch should return a Launch by ID
func (s *mockStoreSvc) GetLaunch(ctx context.Context, id uuid.UUID) (peregrine.Launch, error) {
	l := peregrine.Launch{}
	if id == testLaunchID {
		l.ID = testLaunchID
		l.Nonce = testNonce
		l.Registration = &peregrine.Registration{
			ID:       testRegistrationID,
			ClientID: testClientID,
			Platform: &happyPathPlatform,
		}
	} else if id == testLaunchWithDeploymentID {
		l.ID = testLaunchWithDeploymentID
		l.Nonce = testNonce
		l.Registration = &peregrine.Registration{
			ID:       testRegistrationID,
			ClientID: testClientID,
			Platform: &happyPathPlatform,
		}
		l.Deployment = &peregrine.Deployment{
			ID:                   testDeploymentID,
			PlatformDeploymentID: testPlatformDeploymentID,
		}
	} else {
		return l, fmt.Errorf("LAUNCH_NOT_FOUND")
	}
	return l, nil
}

// CreateLaunch should create a Launch returning Launch with ID and Nonce
func (s *mockStoreSvc) CreateLaunch(ctx context.Context, launch peregrine.Launch) (peregrine.Launch, error) {
	launch.ID = testLaunchID
	launch.Nonce = testNonce
	return launch, nil
}

// UpdateLaunch should update a Launch by ID
func (s *mockStoreSvc) UpdateLaunch(ctx context.Context, launch peregrine.Launch) (peregrine.Launch, error) {
	return launch, nil
}

// -- failure mocks
type mockStoreSvcWithFailedLaunchCreate struct {
	mockStoreSvc
}

func (s *mockStoreSvcWithFailedLaunchCreate) CreateLaunch(ctx context.Context, launch peregrine.Launch) (peregrine.Launch, error) {
	return launch, fmt.Errorf("test create launch failed")
}

type mockStoreSvcWithFailedDeploymentUpsert struct {
	mockStoreSvc
}

func (s *mockStoreSvcWithFailedDeploymentUpsert) UpsertDeploymentByPlatformDeploymentID(ctx context.Context, deployment peregrine.Deployment) (peregrine.Deployment, error) {
	return deployment, fmt.Errorf("upsert deployment forced failure")
}

type mockStoreSvcWithFailedLaunchUpdate struct {
	mockStoreSvc
}

func (s *mockStoreSvcWithFailedLaunchUpdate) UpdateLaunch(ctx context.Context, launch peregrine.Launch) (peregrine.Launch, error) {
	return launch, fmt.Errorf("update launch forced failure")
}

type mockStoreSvcWithFailedPlatformInstanceUpsert struct {
	mockStoreSvc
}

func (s *mockStoreSvcWithFailedPlatformInstanceUpsert) UpsertPlatformInstanceByGUID(ctx context.Context, instance peregrine.PlatformInstance) (peregrine.PlatformInstance, error) {
	return instance, fmt.Errorf("upsert platform instance forced failure")
}

type mockStoreSvcWithRegistrationNotFound struct {
	mockStoreSvc
}

func (s *mockStoreSvcWithRegistrationNotFound) GetRegistrationByClientID(ctx context.Context, clientId string) (peregrine.Registration, error) {
	return peregrine.Registration{}, fmt.Errorf("REGISTRATION_NOT_FOUND")
}
