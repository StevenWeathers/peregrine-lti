package peregrine

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Platform represents the LMS Platform unique by Issuer
type Platform struct {
	// ID (REQUIRED) is the tools UUID for the Platform
	ID uuid.UUID
	// Issuer (REQUIRED) is the id_token JWT issuer ex. https://canvas.instructure.com
	Issuer string
	// KeySetURL (REQUIRED) or URL for the Platform JWK key set ex. https://sso.canvaslms.com/api/lti/authorize_redirect
	KeySetURL string
	// AuthLoginURL (REQUIRED) is the url for the Platform launch authentication
	AuthLoginURL string
}

// PlatformInstance composes properties associated with the platform instance initiating the launch
// optional https://purl.imsglobal.org/spec/lti/claim/tool_platform claim.
//
// In a multi-tenancy case, a single platform (iss) will host multiple instances,
// but each LTI message is originating from a single instance identified by its guid.
type PlatformInstance struct {
	// ID (REQUIRED) is the tools UUID for the PlatformInstance
	ID uuid.UUID
	// Platform (REQUIRED) is the Platform in which the Instance lives
	Platform *Platform
	// GUID (REQUIRED)
	// A stable locally unique to the iss identifier for an instance of the tool platform.
	// The value of guid is a case-sensitive string that MUST NOT exceed 255 ASCII characters in length.
	// The use of Universally Unique IDentifier (UUID) defined in [RFC4122] is recommended.
	GUID string
	// ContactEmail (OPTIONAL). Administrative contact email for the platform instance.
	ContactEmail string
	// Description (OPTIONAL). Descriptive phrase for the platform instance.
	Description string
	// Name (OPTIONAL). Name for the platform instance.
	Name string
	// URL (OPTIONAL). Home HTTPS URL endpoint for the platform instance.
	URL string
	// ProductFamilyCode (OPTIONAL). Vendor product family code for the type of platform.
	ProductFamilyCode string
	// Version (OPTIONAL). Vendor product version for the platform.
	Version string
}

// Registration is the installation of an LTI in a platform instance
type Registration struct {
	// ID is the tools UUID for the Tool Registration
	ID uuid.UUID
	// Platform (REQUIRED) is the Platform in which the Tool is Registered
	Platform *Platform
	// ClientID (REQUIRED) or client_id is the tool registration ID in the Platform Instance
	ClientID string
}

// Deployment
// A deployment of a tool defines the scope of contexts under which a tool is made available.
// For example, a tool may be deployed by the instructor into a single course,
// or the institution may deploy a tool across the whole institution, available to all institution's contexts,
// present and future. For further details see https://www.imsglobal.org/spec/lti/v1p3#tool-deployment
type Deployment struct {
	// ID (REQUIRED) is the tools UUID for the Tool Deployment
	ID uuid.UUID
	// PlatformDeploymentID (REQUIRED)
	// When a user deploys a tool within their tool platform, the platform MUST generate an immutable deployment_id
	// identifier to identify the integration.
	PlatformDeploymentID string
	// Registration (REQUIRED) is the Deployment of to the Registration in the Platform
	Registration *Registration
	// Name (OPTIONAL) for the Deployment location e.g. Global or Sub account
	Name string
	// Description (OPTIONAL) of the Deployment e.g. In Course Navigation
	Description string
}

// Launch is the LTI tool launch event in the PlatformInstance
type Launch struct {
	// ID (REQUIRED) is the tools UUID for the Launch event
	ID uuid.UUID
	// Nonce (REQUIRED) is the tools UNIQUE Nonce for the Launch event
	Nonce uuid.UUID
	// Registration (REQUIRED) is the Registration in which the Launch event occurred
	Registration *Registration
	// Deployment (OPTIONAL) is the Deployment in which the Launch event occurred
	Deployment *Deployment
	// PlatformInstance (OPTIONAL) is the PlatformInstance in which the Launch event occurred
	PlatformInstance *PlatformInstance
	// Used (OPTIONAL) is the timestamp of when the Launch was completed, upon completion the
	// Launch should not be reusable (whether querying by Nonce or ID)
	Used *time.Time
}

// ToolDataRepo is intended to be a storage (e.g. DB) service for an LTI Tools registration and launch
type ToolDataRepo interface {
	// GetPlatformInstanceByGUID should return a PlatformInstance by GUID
	GetPlatformInstanceByGUID(ctx context.Context, guid string) (PlatformInstance, error)
	// GetRegistrationByClientID should return a Registration by ClientID
	GetRegistrationByClientID(ctx context.Context, clientId string) (Registration, error)
	// GetDeploymentByPlatformDeploymentID should return a Deployment by PlatformDeploymentID
	GetDeploymentByPlatformDeploymentID(ctx context.Context, deploymentId string) (Deployment, error)
	// GetLaunch should return a Launch by ID
	GetLaunch(ctx context.Context, id uuid.UUID) (Launch, error)
	// CreateLaunch should create a Launch returning Launch with ID and Nonce
	CreateLaunch(ctx context.Context, launch Launch) (Launch, error)
	// UpdateLaunch should update a Launch by ID
	UpdateLaunch(ctx context.Context, launch Launch) (Launch, error)
}
