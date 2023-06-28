package peregrine_lti

import (
	"github.com/stevenweathers/peregrine-lti/launch"
	"github.com/stevenweathers/peregrine-lti/peregrine"
)

// New returns a new launch.Service
func New(dataSvc peregrine.ToolDataRepo) *launch.Service {
	return launch.New(dataSvc)
}
