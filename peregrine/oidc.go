package peregrine

// OIDCLoginRequestParams as documented here
// http://www.imsglobal.org/spec/security/v1p0/#step-1-third-party-initiated-login
// extended by the following parameters
// https://www.imsglobal.org/spec/lti/v1p3#additional-login-parameters
type OIDCLoginRequestParams struct {
	// Issuer "iss" (REQUIRED) the issuer identifier identifying the learning platform
	Issuer string
	// LoginHint "login_hint" (REQUIRED)
	// Hint to the Authorization Server about the login identifier the End-User might use to log in.
	// The permitted values will be defined in the host specification.
	LoginHint string
	// TargetLinkURI "target_link_uri" (REQUIRED)
	// The actual end-point that should be executed at the end of the OpenID Connect authentication flow.
	TargetLinkURI string
	// LTIMessageHint "lti_message_hint" (OPTIONAL)
	// If present in the login initiation request, the tool MUST include it back in the authentication request unaltered.
	LTIMessageHint string
	// ClientID "client_id" (OPTIONAL)
	// The new optional parameter client_id specifies the client id for the authorization server that should be used to
	// authorize the subsequent LTI message request. This allows for a platform to support multiple registrations from
	// a single issuer, without relying on the initiate_login_uri as a key.
	ClientID string
	// LTIDeploymentID "lti_deployment_id" (OPTIONAL)
	// The new optional parameter lti_deployment_id that if included, MUST contain the same deployment id that would be
	// passed in the https://purl.imsglobal.org/spec/lti/claim/deployment_id claim for the subsequent LTI message launch.
	LTIDeploymentID string
}

// OIDCLoginResponseParams as documented here
// http://www.imsglobal.org/spec/security/v1p0/#step-2-authentication-request
type OIDCLoginResponseParams struct {
	//SCOPE "scope": "openid" (REQUIRED) as per [OPENID-CCORE].
	Scope string
	//ResponseType "response_type": "id_token" (REQUIRED) as per [OPENID-CCORE]
	ResponseType string
	// ClientID "client_id" (REQUIRED) as per [OPENID-CCORE]. The Tool’s Client ID for this issuer.
	ClientID string
	// RedirectURI "redirect_uri" (REQUIRED) as per [OPENID-CCORE]. One of the registered redirect URIs.
	RedirectURI string
	// LoginHint "login_hint" (REQUIRED) As passed in the initiate login request.
	LoginHint string
	// State "state" (RECOMMENDED) as per [OPENID-CCORE].
	// Opaque value for the platform to maintain state between the request and callback and provide
	// Cross-Site Request Forgery (CSRF) mitigation.
	State string
	// ResponseMode "response_mode": "form_post" (REQUIRED)
	// The Token can be lengthy and thus should be passed over as a form POST.
	ResponseMode string
	// Nonce "nonce" (REQUIRED).
	// String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
	//The value is passed through unmodified from the Authentication Request to the ID Token.
	Nonce string
	// Prompt "prompt": "none" (REQUIRED).
	// Since the message launch is meant to be sent from a platform where the user is already logged in.
	// If the user has no session, a platform must just fail the flow rather than ask the user to log in.
	Prompt string
	// LTIMessageHint "lti_message_hint" (OPTIONAL)
	// If present in the login initiation request, the tool MUST include it back in the authentication request unaltered.
	LTIMessageHint string
}

// OIDCAuthenticationResponse as documented here
// http://www.imsglobal.org/spec/security/v1p0/#step-3-authentication-response
type OIDCAuthenticationResponse struct {
	// State "state" (REQUIRED) must match the OIDCLoginResponseParams State
	State string
	// IDToken "id_token" (REQUIRED) - see Section 3.2.2.5 of the [OPENID-CCORE].
	// This also contains the other message specific claims and the nonce passed in the auth request.
	IDToken string
}
