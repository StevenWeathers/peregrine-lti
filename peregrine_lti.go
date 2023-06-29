package peregrine_lti

import (
	"github.com/stevenweathers/peregrine-lti/launch"
	"github.com/stevenweathers/peregrine-lti/peregrine"
)

// New returns a new launch.Service
func New(config launch.Config, dataSvc peregrine.ToolDataRepo) *launch.Service {
	return launch.New(config, dataSvc)
}
