package peregrine

// OIDCLoginRequestParams as documented here
// http://www.imsglobal.org/spec/security/v1p0/#step-1-third-party-initiated-login
// extended by the following parameters
// https://www.imsglobal.org/spec/lti/v1p3#additional-login-parameters
type OIDCLoginRequestParams struct {
	// Issuer (REQUIRED) the issuer identifier identifying the learning platform
	Issuer string `json:"iss"`
	// LoginHint (REQUIRED)
	// Hint to the Authorization Server about the login identifier the End-User might use to log in.
	// The permitted values will be defined in the host specification.
	LoginHint string `json:"login_hint"`
	// TargetLinkURI (REQUIRED)
	// The actual end-point that should be executed at the end of the OpenID Connect authentication flow.
	TargetLinkURI string `json:"target_link_uri"`
	// LTIMessageHint (OPTIONAL)
	// If present in the login initiation request, the tool MUST include it back in the authentication request unaltered.
	LTIMessageHint string `json:"lti_message_hint"`
	// ClientID (OPTIONAL)
	// The new optional parameter client_id specifies the client id for the authorization server that should be used to
	// authorize the subsequent LTI message request. This allows for a platform to support multiple registrations from
	// a single issuer, without relying on the initiate_login_uri as a key.
	ClientID string `json:"client_id"`
	// LTIDeploymentID (OPTIONAL)
	// The new optional parameter lti_deployment_id that if included, MUST contain the same deployment id that would be
	// passed in the https://purl.imsglobal.org/spec/lti/claim/deployment_id claim for the subsequent LTI message launch.
	LTIDeploymentID string `json:"lti_deployment_id"`
}

// OIDCLoginResponseParams as documented here
// http://www.imsglobal.org/spec/security/v1p0/#step-2-authentication-request
type OIDCLoginResponseParams struct {
	//SCOPE (REQUIRED) must be set to "openid" as per [OPENID-CCORE].
	Scope string `json:"scope"`
	//ResponseType (REQUIRED) must be set to "id_token" as per [OPENID-CCORE]
	ResponseType string `json:"response_type"`
	// ClientID (REQUIRED) as per [OPENID-CCORE]. The Tool’s Client ID for this issuer.
	ClientID string `json:"client_id"`
	// RedirectURI (REQUIRED) as per [OPENID-CCORE]. One of the registered redirect URIs.
	RedirectURI string `json:"redirect_uri"`
	// LoginHint (REQUIRED) As passed in the initiate login request.
	LoginHint string `json:"login_hint"`
	// State (RECOMMENDED) as per [OPENID-CCORE].
	// Opaque value for the platform to maintain state between the request and callback and provide
	// Cross-Site Request Forgery (CSRF) mitigation.
	State string `json:"state"`
	// ResponseMode (REQUIRED) must be set to "form_post"
	// The Token can be lengthy and thus should be passed over as a form POST.
	ResponseMode string `json:"response_mode"`
	// Nonce (REQUIRED).
	// String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
	//The value is passed through unmodified from the Authentication Request to the ID Token.
	Nonce string `json:"nonce"`
	// Prompt (REQUIRED) Must be set to "none"
	// Since the message launch is meant to be sent from a platform where the user is already logged in.
	// If the user has no session, a platform must just fail the flow rather than ask the user to log in.
	Prompt string `json:"prompt"`
	// LTIMessageHint (OPTIONAL)
	// If present in the login initiation request, the tool MUST include it back in the authentication request unaltered.
	LTIMessageHint string `json:"lti_message_hint"`
}

// OIDCAuthenticationResponse as documented here
// http://www.imsglobal.org/spec/security/v1p0/#step-3-authentication-response
type OIDCAuthenticationResponse struct {
	// State (REQUIRED) must match the OIDCLoginResponseParams State
	State string `json:"state"`
	// IDToken (REQUIRED) - see Section 3.2.2.5 of the [OPENID-CCORE].
	// This also contains the other message specific claims and the nonce passed in the auth request.
	IDToken string `json:"id_token"`
}

// IDToken or id_token as documented here
// http://www.imsglobal.org/spec/security/v1p0/#id-token
type IDToken struct {
	// Issuer (REQUIRED)
	// Issuer Identifier for the Issuer of the message i.e. the Platform.
	// The iss value is a case-sensitive URL using the HTTPS scheme that contains:
	// scheme, host; and, optionally, port number, and path components; and, no query or fragment components.
	Issuer string `json:"iss"`
	// AUD (REQUIRED)
	// Audience(s) for whom this ID Token is intended i.e. the Tool.
	// It MUST contain the OAuth 2.0 client_id of the Tool as an audience value.
	// It MAY also contain identifiers for other audiences.
	// In the general case, the aud value is an array of case-sensitive strings.
	// In the common special case when there is one audience, the aud value MAY be a single case-sensitive string.
	AUD string `json:"aud"`
	// SUB (REQUIRED)
	// Subject Identifier. A locally unique and never reassigned identifier within the Issuer for the end user,
	// which is intended to be consumed by the Tool. It MUST NOT exceed 255 ASCII characters in length.
	// The sub value is a case-sensitive string. This MUST be the same value as the Platform's User ID for the end user.
	SUB string `json:"sub"`
	// EXP "exp" (REQUIRED)
	// Expiration time on or after which the Tool MUST NOT accept the ID Token for processing.
	// When processing this parameter, the Tool MUST verify that the time expressed in this Claim occurs after the
	// current date/time. Implementers MAY provide for some small leeway, usually no more than a few minutes,
	// to account for clock skew. This Claim's value MUST be a JSON number representing the number of seconds offset
	// from 1970-01-01T00:00:00Z (UTC). See [RFC3339] for details regarding date/times in general and UTC in particular.
	EXP string `json:"exp"`
	// IAT (REQUIRED)
	// Time at which the Issuer generated the JWT. Its value is a JSON number representing the number of seconds offset from 1970-01-01T00:00:00Z (UTC) until the generation time.
	IAT string `json:"iat"`
	// Nonce (REQUIRED)
	// String value used to associate a Tool session with an ID Token, and to mitigate replay attacks.
	// The nonce value is a case-sensitive string.
	Nonce string `json:"nonce"`
	// AZP (OPTIONAL) Authorized party - the party to which the ID Token was issued.
	// If present, it MUST contain the OAuth 2.0 Tool ID of this party.
	// This Claim is only needed when the Token has a single audience value and that audience is different than
	// the authorized party. It MAY be included even when the authorized party is the same as the sole audience.
	// The azp value is a case-sensitive string containing a String or URI value.
	AZP string `json:"azp"`
}
