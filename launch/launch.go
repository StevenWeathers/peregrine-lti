package launch

import (
	"context"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stevenweathers/peregrine-lti/peregrine"
)

// Service provides utilities for the LTI launch
type Service struct {
	dataSvc  peregrine.ToolDataRepo
	jwkCache *jwk.Cache
}

func New(dataSvc peregrine.ToolDataRepo) *Service {
	c := jwk.NewCache(context.Background())
	return &Service{
		dataSvc:  dataSvc,
		jwkCache: c,
	}
}

func (s *Service) getPlatformJWKs(ctx context.Context, jwkURL string) (jwk.Set, error) {
	if !s.jwkCache.IsRegistered(jwkURL) {
		err := s.jwkCache.Register(jwkURL)
		return nil, err
	}
	return s.jwkCache.Refresh(ctx, jwkURL)
}