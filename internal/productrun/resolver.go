package productrun

import (
	"errors"

	"github.com/whyiug/agentapi-doctor/internal/executor"
	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

// ExactResolver binds one runner to one complete ArtifactPin. Name or version
// matches are insufficient: kind, name, exact version, and digest must all be
// identical to the ResolvedRunPlan decision.
type ExactResolver struct {
	pin    schema.ArtifactPin
	runner executor.Runner
}

func NewExactResolver(pin schema.ArtifactPin, runner executor.Runner) (*ExactResolver, error) {
	if err := pin.Validate(); err != nil {
		return nil, err
	}
	if runner == nil {
		return nil, errors.New("runner is required")
	}
	return &ExactResolver{pin: pin, runner: runner}, nil
}

func (resolver *ExactResolver) Resolve(pin schema.ArtifactPin) (executor.Runner, error) {
	if resolver == nil || resolver.runner == nil {
		return nil, errors.New("runner resolver is not initialized")
	}
	if pin != resolver.pin {
		return nil, errors.New("runner pin does not exactly match the resolved driver artifact")
	}
	return resolver.runner, nil
}
