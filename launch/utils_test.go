package launch

import (
	"context"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stevenweathers/peregrine-lti/peregrine"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestGetPlatformJWKs(t *testing.T) {
	c := jwk.NewCache(context.Background())
	keySet, err := getPlatformJWKs(context.Background(), c, srvUrl+"/canvaslms/api/lti/security/jwks")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, found := keySet.LookupKeyID("testkey")
	if !found {
		t.Fatalf("expected testkey to be found in jwks")
	}

	_, err = getPlatformJWKs(context.Background(), c, srvUrl+"/canvaslms/api/lti/security/badjwks")
	if err == nil || !strings.Contains(err.Error(), "failed to refresh platform keyset") {
		t.Fatalf("expected error for getPlatformJWKs")
	}
}

func TestCreateLaunchState(t *testing.T) {
	launchState, err := createLaunchState(happyPathIssuer, testJWTSecret, happyPathLaunchID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if launchState == "" {
		t.Fatal("expected launch state to not be empty string")
	}

	key, _ := jwk.FromRaw([]byte(testJWTSecret))
	verifiedToken, _ := jwt.Parse([]byte(launchState), jwt.WithKey(jwa.HS256, key))
	claims := verifiedToken.PrivateClaims()
	lid, ok := claims[launchIDClaim]
	if !ok || lid.(string) != happyPathLaunchID.String() {
		t.Fatalf("expected state launch ID %s to equal %s", lid.(string), happyPathLaunchID.String())
	}
}

func TestGetLoginParamsFromRequestFormValues(t *testing.T) {
	urlValues := url.Values{}
	urlValues.Add("iss", "test_iss")
	urlValues.Add("login_hint", "test_login_hint")
	urlValues.Add("target_link_uri", "test_target_link_uri")
	urlValues.Add("lti_message_hint", "test_lti_message_hint")
	urlValues.Add("client_id", "test_client_id")
	urlValues.Add("lti_deployment_id", "test_deployment_id")
	params, err := GetLoginParamsFromRequestFormValues(&http.Request{
		Form: urlValues,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if params.Issuer != "test_iss" {
		t.Fatalf("expected issuer %s to equal test_iss", params.Issuer)
	}
	if params.LoginHint != "test_login_hint" {
		t.Fatalf("expected login_hint %s to equal test_login_hint", params.LoginHint)
	}
	if params.TargetLinkURI != "test_target_link_uri" {
		t.Fatalf("expected target_link_uri %s to equal test_target_link_uri", params.TargetLinkURI)
	}
	if params.ClientID != "test_client_id" {
		t.Fatalf("expected client_id %s to equal test_client_id", params.ClientID)
	}
	if params.LTIMessageHint != "test_lti_message_hint" {
		t.Fatalf("expected lti_message_hint %s to equal test_lti_message_hint", params.LTIMessageHint)
	}
	if params.LTIDeploymentID != "test_deployment_id" {
		t.Fatalf("expected lti_deployment_id %s to equal test_deployment_id", params.LTIDeploymentID)
	}

}

func TestGetCallbackParamsFromRequestFormValues(t *testing.T) {
	urlValues := url.Values{}
	urlValues.Add("state", "test_state")
	urlValues.Add("id_token", "test_id_token")
	params, err := GetCallbackParamsFromRequestFormValues(&http.Request{
		Form: urlValues,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if params.State != "test_state" {
		t.Fatalf("expected state %s to equal test_state", params.State)
	}
	if params.IDToken != "test_id_token" {
		t.Fatalf("expected id_token %s to equal test_id_token", params.IDToken)
	}
}

func TestBuildLoginResponseRedirectURL(t *testing.T) {
	expectedRedirUrl := "?client_id=test_client_id&login_hint=test_login_hint&lti_message_hint=test_lti_message_hint&nonce=test_nonce&prompt=none&redirect_uri=%2Flti%2Fcallback&response_mode=form_post&response_type=id_token&scope=openid&state=test_state"
	redirUrl, err := BuildLoginResponseRedirectURL(
		peregrine.OIDCLoginResponseParams{
			Scope:          "openid",
			ResponseType:   "id_token",
			ResponseMode:   "form_post",
			Prompt:         "none",
			ClientID:       "test_client_id",
			LoginHint:      "test_login_hint",
			LTIMessageHint: "test_lti_message_hint",
			State:          "test_state",
			Nonce:          "test_nonce",
		}, "", "/lti/callback",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if redirUrl != expectedRedirUrl {
		t.Fatalf("expected redirect URL to be %s got %s", expectedRedirUrl, redirUrl)
	}
}
