package launch

import (
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stevenweathers/peregrine-lti/peregrine"
)

// Config holds all the configuration's for Service
type Config struct {
	// Issuer (REQUIRED) is the issuer used to sign the state JWT
	Issuer string
	// JWTKeySecret (REQUIRED) is the secret used to create the state JWT
	JWTKeySecret string
}

// Service provides handlers for the LTI launch
type Service struct {
	config   Config
	dataSvc  peregrine.ToolDataRepo
	jwkCache *jwk.Cache
}

// HandleOidcLoginResponse contains the login params and redirect url to proceed with LTI launch
type HandleOidcLoginResponse struct {
	OIDCLoginResponseParams peregrine.OIDCLoginResponseParams
	// RedirectURL is the url for the Platform launch authentication
	RedirectURL string
}

// HandleOidcCallbackResponse contains the lti 1.3 claims and peregrine.Launch of the successful LTI launch
type HandleOidcCallbackResponse struct {
	Claims peregrine.LTI1p3Claims
	Launch peregrine.Launch
}
