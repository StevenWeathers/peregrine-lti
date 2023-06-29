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
	//
	// At times the platform may wish to send anonymous request messages to avoid sending identifying user information
	// to the tool. To accommodate for this case, the platform may in these cases not include the sub claim
	// or any other user identity claims. The tool must interpret the lack of a sub claim as a launch request coming
	// from an anonymous user.
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

// ResourceLinkClaim as per https://www.imsglobal.org/spec/lti/v1p3#resource-link-claim
type ResourceLinkClaim struct {
	// ID (REQUIRED) Opaque identifier for a placement of an LTI resource link within a context that
	// MUST be a stable and locally unique to the deployment_id. This value MUST change if the link is copied
	// or exported from one system or context and imported into another system or context.
	// The value of id MUST NOT exceed 255 ASCII characters in length and is case-sensitive.
	ID string `json:"id"`
	// Description (OPTIONAL) descriptive phrase for an LTI resource link placement
	Description string `json:"description"`
	// Title (OPTIONAL) descriptive title for an LTI resource link placement
	Title string `json:"title"`
}

// ContextClaim as per https://www.imsglobal.org/spec/lti/v1p3#context-claim
type ContextClaim struct {
	// ID (REQUIRED) Stable identifier that uniquely identifies the context from which the LTI message initiates.
	// The context id MUST be locally unique to the deployment_id.
	// It is recommended to also be locally unique to iss (Issuer).
	// The value of id MUST NOT exceed 255 ASCII characters in length and is case-sensitive.
	ID string `json:"id"`
	// Type (OPTIONAL) An array of URI values for context types. If present, the array MUST include at least one
	// context type from the context type vocabulary described in context type vocabulary.
	// If the sender of the message wants to include a context type from another vocabulary namespace, by best practice
	// it should use a fully-qualified URI. By best practice, systems should not use context types from another role
	// vocabulary, as this may limit interoperability.
	Type []string `json:"type"`
	// Label (OPTIONAL) Short descriptive name for the context.
	// This often carries the "course code" for a course offering or course section context.
	Label string `json:"label"`
	// Title (OPTIONAL) Full descriptive name for the context.
	// This often carries the "course title" or "course name" for a course offering context.
	Title string `json:"title"`
}

// PlatformInstanceClaim as per https://www.imsglobal.org/spec/lti/v1p3#platform-instance-claim
type PlatformInstanceClaim struct {
	// GUID (REQUIRED) A stable locally unique to the iss identifier for an instance of the tool platform.
	// The value of guid is a case-sensitive string that MUST NOT exceed 255 ASCII characters in length.
	// The use of Universally Unique IDentifier (UUID) defined in [RFC4122] is recommended.
	GUID string `json:"guid"`
	// ContactEmail (OPTIONAL) Administrative contact email for the platform instance.
	ContactEmail string `json:"contact_email"`
	// Description (OPTIONAL) Descriptive phrase for the platform instance.
	Description string `json:"description"`
	// Name (OPTIONAL) Name for the platform instance.
	Name string `json:"name"`
	// URL (OPTIONAL) Home HTTPS URL endpoint for the platform instance.
	URL string `json:"url"`
	// ProductFamilyCode (OPTIONAL) Vendor product family code for the type of platform.
	ProductFamilyCode string `json:"product_family_code"`
	// Version (OPTIONAL). Vendor product version for the platform.
	Version string `json:"version"`
}

// LaunchPresentationClaim as per https://www.imsglobal.org/spec/lti/v1p3#launch-presentation-claim
type LaunchPresentationClaim struct {
	// DocumentTarget (OPTIONAL). The kind of browser window or frame from which the user launched inside
	// the message sender's system. The value for this property MUST be one of: frame, iframe, or window.
	DocumentTarget string `json:"document_target"`
	// Height (OPTIONAL)
	// height of the window or frame where the content from the message receiver will be displayed to the user.
	Height string `json:"height"`
	// Weight (OPTIONAL)
	// width of the window or frame where the content from the message receiver will be displayed to the user.
	Weight string `json:"width"`
	// ReturnURL (OPTIONAL)
	// Fully-qualified HTTPS URL within the message sender's user experience to where the message receiver can
	// redirect the user back. The message receiver can redirect to this URL after the user has finished activity,
	// or if the receiver cannot start because of some technical difficulty.
	ReturnURL string `json:"return_url"`
	// Locale (OPTIONAL)
	// Language, country, and variant as represented using the IETF Best Practices for Tags for Identifying Languages [BCP47].
	Locale string `json:"locale"`
}

// LISClaim as per https://www.imsglobal.org/spec/lti/v1p3#lislti
type LISClaim struct {
	// CourseOfferingSourceddID (OPTIONAL)
	// The LIS course offering identifier applicable to the context of this basic LTI launch request message.
	CourseOfferingSourceddID string `json:"course_offering_sourcedid"`
	// CourseSectionSourcedID (OPTIONAL)
	// The LIS course section identifier applicable to the context of this basic LTI launch request message.
	CourseSectionSourcedID string `json:"course_section_sourcedid"`
	// OutcomeServiceURL (OPTIONAL)
	// URL endpoint for the LTI Basic Outcomes Service [LTI-BO-11].
	// By best practice, this URL should not change from one resource link launch request message to the next;
	// platforms should provide a single, unchanging endpoint URL for each registered tool.
	// This URL endpoint may support various operations/actions; by best practice, the provider of an LTI Basic
	// Outcome Service should respond with a response of unimplemented for actions it does not support.
	OutcomeServiceURL string `json:"outcome_service_url"`
	// PersonSourcedID (OPTIONAL)
	// The LIS identifier for the user account that initiated the resource link launch request.
	// The exact format of the sourced ID may vary with the LIS integration;
	// it is simply a unique identifier for the launching user.
	PersonSourcedID string `json:"person_sourcedid"`
	// PersonNameFull (OPTIONAL)
	// Some LIS-known names for the user account that initiated the resource link launch request.
	// The content and meaning of these fields are defined by LIS v2.0 [LIS-20].
	PersonNameFull string `json:"person_name_full"`
	// PersonNameGiven (OPTIONAL)
	// Some LIS-known names for the user account that initiated the resource link launch request.
	// The content and meaning of these fields are defined by LIS v2.0 [LIS-20].
	PersonNameGiven string `json:"person_name_given"`
	// PersonNameFamily (OPTIONAL)
	// Some LIS-known names for the user account that initiated the resource link launch request.
	// The content and meaning of these fields are defined by LIS v2.0 [LIS-20].
	PersonNameFamily string `json:"person_name_family"`
	// PersonContactEmailPrimary (OPTIONAL).
	// The LIS-known primary email contactinfo for the user account that initiated the resource link launch request.
	// The content and meaning of this field is defined by LIS v2.0 [LIS-20].
	PersonContactEmailPrimary string `json:"person_contact_email_primary"`
	// ResultSourcedID(OPTIONAL)
	// An opaque identifier that indicates the LIS Result Identifier (if any) associated with the resource link
	// launch request (identifying a unique row and column within the service provider's gradebook).
	ResultSourcedID string `json:"result_sourcedid"`
}

// LTI1p3Claims contains all the claims as per the LTI 1.3 spec
// see https://www.imsglobal.org/spec/lti/v1p3#required-message-claims
// and https://www.imsglobal.org/spec/lti/v1p3#optional-message-claims
// and https://www.imsglobal.org/spec/lti/v1p3#user-identity-claims
// see example of full claims at https://www.imsglobal.org/spec/lti/v1p3#examplelinkrequest
type LTI1p3Claims struct {
	// MessageType (REQUIRED) claim's value contains a string that indicates the type of the sender's LTI message.
	// For conformance with this specification, the claim must have the value LtiResourceLinkRequest.
	MessageType string `json:"https://purl.imsglobal.org/spec/lti/claim/message_type"`
	// Version (REQUIRED)
	// Claim's value contains a string that indicates the version of LTI to which the message conforms.
	// For conformance with this specification, the claim must have the value 1.3.0.
	Version string `json:"https://purl.imsglobal.org/spec/lti/claim/version"`
	// DeploymentID (REQUIRED)
	// Claim's value contains a case-sensitive string that identifies the platform-tool integration governing the message.
	// It MUST NOT exceed 255 ASCII characters in length.
	DeploymentID string `json:"https://purl.imsglobal.org/spec/lti/claim/deployment_id"`
	// TargetLinkURI (REQUIRED) MUST be the same value as the target_link_uri passed by the platform
	// in the OIDC third party initiated login request.
	TargetLinkURI string `json:"https://purl.imsglobal.org/spec/lti/claim/target_link_uri"`
	// ResourceLinkClaim (REQUIRED)
	// Claim composes properties for the resource link from which the launch message occurs
	ResourceLink ResourceLinkClaim `json:"https://purl.imsglobal.org/spec/lti/claim/resource_link "`
	// SUB (OPTIONAL)
	// This is the only required user claim (except, see anonymous launch case following).
	// When included, per OIDC specifications, the sub (Subject) MUST be a stable locally unique to the iss (Issuer)
	// identifier for the actual, authenticated End-User that initiated the launch.
	// It MUST NOT exceed 255 ASCII characters in length and is case-sensitive.
	//
	// At times the platform may wish to send anonymous request messages to avoid sending identifying user information
	// to the tool. To accommodate for this case, the platform may in these cases not include the sub claim
	// or any other user identity claims. The tool must interpret the lack of a sub claim as a launch request coming
	// from an anonymous user.
	SUB string `json:"sub"`
	// GivenName (OPTIONAL) Per OIDC specifications, given name(s) or first name(s) of the End-User.
	// Note that in some cultures, people can have multiple given names; all can be present,
	// with the names being separated by space characters.
	GivenName string `json:"given_name"`
	// FamilyName (OPTIONAL) Per OIDC specifications, surname(s) or last name(s) of the End-User.
	// Note that in some cultures, people can have multiple family names or no family name; all can be present,
	// with the names being separated by space characters.
	FamilyName string `json:"family_name"`
	// Name (OPTIONAL) Per OIDC specifications, end-User's full name in displayable form including all name parts,
	// possibly including titles and suffixes, ordered according to the End-User's locale and preferences.
	Name string `json:"name"`
	// Email (OPTIONAL) Per OIDC specifications, end-User's preferred e-mail address.
	Email string `json:"email"`
	// Locale Per OIDC specifications, end-User's preferred locale as a BCP47 language tag.
	Locale string `json:"locale"`
	// Roles (REQUIRED) claim's value contains a (possibly empty) array of URI values for roles that the user
	// has within the message's associated context.
	Roles []string `json:"https://purl.imsglobal.org/spec/lti/claim/roles"`
	// The optional  claim composes properties for the context from within which the resource link launch occurs. The following is an example of this claim as if the resource link launch is in the context of a course:
	Context ContextClaim `json:"https://purl.imsglobal.org/spec/lti/claim/context"`
	// ToolPlatform (OPTIONAL) claim composes properties associated with the platform instance initiating the launch.
	ToolPlatform PlatformInstanceClaim `json:"https://purl.imsglobal.org/spec/lti/claim/tool_platform"`
	// RoleScopeMentor (OPTIONAL) claim's value contains an array of the user ID values which the current,
	// launching user can access as a mentor (for example, the launching user may be a parent or auditor of a list
	// of other users)
	RoleScopeMentor []string `json:"https://purl.imsglobal.org/spec/lti/claim/role_scope_mentor"`
	// LaunchPresentation (OPTIONAL) claim composes properties that describe aspects of how the message sender
	// expects to host the presentation of the message receiver's user experience
	// (for example, the height and width of the viewport the message sender gives over to the message receiver)
	LaunchPresentation LaunchPresentationClaim `json:"https://purl.imsglobal.org/spec/lti/claim/launch_presentation"`
	// LIS (OPTIONAL) claim's value composes properties about available Learning Information Services (LIS),
	// usually originating from the Student Information System
	LIS LISClaim `json:"https://purl.imsglobal.org/spec/lti/claim/lis"`
	// Custom (OPTIONAL) claim acts like a key-value map of defined custom properties that a platform may associate
	// with the resource link that initiated the launch.
	// Each custom property name appears as a property within the message's top-level custom property.
	// A custom property value must always be of type string. Note that "empty-string" is a valid custom value ("")
	// note also that null is not a valid custom value.
	Custom map[string]string `json:"https://purl.imsglobal.org/spec/lti/claim/custom"`
}
