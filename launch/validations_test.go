package launch

import (
	"github.com/stevenweathers/peregrine-lti/peregrine"
	"testing"
)

func TestValidateLoginRequestParams(t *testing.T) {
	err := validateLoginRequestParams(
		peregrine.OIDCLoginRequestParams{
			Issuer:        "test_issuer",
			ClientID:      "test_client",
			LoginHint:     "test_login_hint",
			TargetLinkURI: "test_target_link_uri",
		},
	)
	if err != nil {
		t.Fatalf(`validateLoginRequestParams = %v error`, err)
	}

	err = validateLoginRequestParams(
		peregrine.OIDCLoginRequestParams{
			Issuer: "",
		},
	)
	if err.Error() != "MISSING_ISS" {
		t.Fatalf(`expected MISSING_ISS error for validateLoginRequestParams`)
	}

	err = validateLoginRequestParams(
		peregrine.OIDCLoginRequestParams{
			Issuer:   "test_issuer",
			ClientID: "",
		},
	)
	if err.Error() != "MISSING_CLIENT_ID" {
		t.Fatalf(`expected MISSING_CLIENT_ID error for validateLoginRequestParams`)
	}

	err = validateLoginRequestParams(
		peregrine.OIDCLoginRequestParams{
			Issuer:    "test_issuer",
			ClientID:  "test_client_id",
			LoginHint: "",
		},
	)
	if err.Error() != "MISSING_LOGIN_HINT" {
		t.Fatalf(`expected MISSING_LOGIN_HINT error for validateLoginRequestParams`)
	}

	err = validateLoginRequestParams(
		peregrine.OIDCLoginRequestParams{
			Issuer:    "test_issuer",
			ClientID:  "test_client_id",
			LoginHint: "test_login_hint",
		},
	)
	if err.Error() != "MISSING_TARGET_LINK_URI" {
		t.Fatalf(`expected MISSING_TARGET_LINK_URI error for validateLoginRequestParams`)
	}
}
