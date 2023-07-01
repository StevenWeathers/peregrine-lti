package store

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stevenweathers/peregrine-lti/peregrine"
)

type LaunchDataService struct {
	DB *pgx.Conn
}

// UpsertPlatformInstanceByGUID should create a PlatformInstance if not existing returning PlatformInstance with ID
func (s *LaunchDataService) UpsertPlatformInstanceByGUID(
	ctx context.Context, instance peregrine.PlatformInstance,
) (peregrine.PlatformInstance, error) {
	platIns := peregrine.PlatformInstance{}

	err := s.DB.QueryRow(ctx,
		`SELECT pi.id, pi.guid
			FROM peregrine.platform_instance pi 
			WHERE pi.guid = $1`,
		instance.GUID,
	).Scan(
		&platIns.ID, &platIns.GUID,
	)
	if err != nil && err == sql.ErrNoRows {
		err := s.DB.QueryRow(ctx,
			`INSERT INTO peregrine.platform_instance 
				(guid, platform_id, contact_email, description, name, url, product_family_code, version)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
			instance.GUID, instance.Platform.ID, instance.ContactEmail, instance.Description,
			instance.Name, instance.URL, instance.ProductFamilyCode, instance.Version,
		).Scan(&platIns.ID)
		if err != nil {
			return platIns, err
		}
	} else if err != nil {
		return platIns, err
	}

	return platIns, err
}

// GetRegistrationByClientID should return a Registration by ClientID
func (s *LaunchDataService) GetRegistrationByClientID(ctx context.Context, clientId string) (peregrine.Registration, error) {
	reg := peregrine.Registration{
		Platform: &peregrine.Platform{},
	}

	err := s.DB.QueryRow(ctx,
		`SELECT r.id, r.client_id, r.platform_id, p.issuer, p.key_set_url, p.auth_login_url
			FROM peregrine.registration r
			JOIN peregrine.platform p ON r.platform_id = p.id 
			WHERE r.client_id = $1`,
		clientId,
	).Scan(
		&reg.ID, &reg.ClientID, &reg.Platform.ID, &reg.Platform.Issuer,
		&reg.Platform.KeySetURL, &reg.Platform.AuthLoginURL,
	)

	return reg, err
}

// UpsertDeploymentByPlatformDeploymentID should create a Deployment if not existing returning a Deployment with ID
func (s *LaunchDataService) UpsertDeploymentByPlatformDeploymentID(
	ctx context.Context, deployment peregrine.Deployment,
) (peregrine.Deployment, error) {
	dep := peregrine.Deployment{
		Registration: &peregrine.Registration{
			Platform: &peregrine.Platform{},
		},
	}

	err := s.DB.QueryRow(ctx,
		`SELECT d.id, d.platform_deployment_id, r.id, p.id, p.key_set_url
			FROM peregrine.deployment d
			JOIN peregrine.registration r ON d.registration_id = r.id
			JOIN peregrine.platform p ON r.platform_id = p.id
			WHERE d.platform_deployment_id = $1`,
		deployment.ID,
	).Scan(
		&dep.ID, &dep.PlatformDeploymentID, &dep.Registration.ID,
		&dep.Registration.Platform.ID, &dep.Registration.Platform.KeySetURL,
	)
	if err != nil && err == sql.ErrNoRows {
		err := s.DB.QueryRow(ctx,
			`INSERT INTO peregrine.deployment 
				(registration_id, platform_deployment_id)
				VALUES ($1, $2) RETURNING id`,
			&deployment.Registration.ID, &deployment.PlatformDeploymentID,
		).Scan(&dep.ID)
		if err != nil {
			return dep, err
		}
	} else if err != nil {
		return dep, err
	}

	return dep, err
}

// GetLaunch should return a Launch by ID
func (s *LaunchDataService) GetLaunch(ctx context.Context, id uuid.UUID) (peregrine.Launch, error) {
	l := peregrine.Launch{
		Registration: &peregrine.Registration{
			Platform: &peregrine.Platform{},
		},
	}

	err := s.DB.QueryRow(ctx,
		`SELECT l.id, l.nonce, r.id, r.client_id, p.id, p.issuer, p.key_set_url, p.auth_login_url
			FROM peregrine.launch l
			JOIN peregrine.registration r ON l.registration_id = r.id
			JOIN peregrine.platform p ON r.platform_id = p.id
			WHERE l.id = $1 AND l.used IS NULL`,
		id,
	).Scan(
		&l.ID, &l.Nonce, &l.Registration.ID, &l.Registration.ClientID,
		&l.Registration.Platform.ID, &l.Registration.Platform.Issuer, &l.Registration.Platform.KeySetURL,
		&l.Registration.Platform.AuthLoginURL,
	)

	return l, err
}

// CreateLaunch should create a Launch returning Launch with ID and Nonce
func (s *LaunchDataService) CreateLaunch(ctx context.Context, launch peregrine.Launch) (peregrine.Launch, error) {
	l := launch

	err := s.DB.QueryRow(ctx,
		`INSERT INTO peregrine.launch (registration_id) VALUES ($1) RETURNING id, nonce`,
		launch.Registration.ID,
	).Scan(
		&l.ID, &l.Nonce,
	)

	return l, err
}

// UpdateLaunch should update a Launch by ID
func (s *LaunchDataService) UpdateLaunch(ctx context.Context, launch peregrine.Launch) (peregrine.Launch, error) {
	l := launch
	return l, nil
}
