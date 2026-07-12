package driverprotocol

import (
	"encoding/json"
	"fmt"
	"sync"

	publicschema "github.com/whyiug/agentapi-doctor/pkg/schema"
)

// State is the serial v1 Driver RPC lifecycle state.
type State string

const (
	StateNew      State = "NEW"
	StateHello    State = "HELLO"
	StatePrepared State = "PREPARED"
	StateInvoking State = "INVOKING"
	StateShutdown State = "SHUTDOWN"
)

// ActiveInvocation is a non-sensitive state-machine snapshot.
type ActiveInvocation struct {
	InvocationID    publicschema.InstanceID
	AttemptID       publicschema.InstanceID
	LastSequence    uint64
	HasObservation  bool
	CancelRequested bool
}

type activeInvocation struct {
	ActiveInvocation
}

// Machine validates one serial Driver RPC lifecycle. It is safe for concurrent
// calls, but concurrency-capable drivers must use a higher-level dispatcher
// that assigns a Machine to each invocation rather than weakening sequence and
// terminal checks here.
type Machine struct {
	mu        sync.Mutex
	state     State
	active    *activeInvocation
	completed map[publicschema.InstanceID]struct{}
}

// NewMachine starts in NEW.
func NewMachine() *Machine {
	return &Machine{
		state:     StateNew,
		completed: make(map[publicschema.InstanceID]struct{}),
	}
}

// State returns the current lifecycle state.
func (machine *Machine) State() State {
	machine.mu.Lock()
	defer machine.mu.Unlock()
	return machine.state
}

// Active returns a copy of the current invocation, if any.
func (machine *Machine) Active() (ActiveInvocation, bool) {
	machine.mu.Lock()
	defer machine.mu.Unlock()
	if machine.active == nil {
		return ActiveInvocation{}, false
	}
	return machine.active.ActiveInvocation, true
}

// AcceptHello advances NEW to HELLO after a successful hello exchange.
func (machine *Machine) AcceptHello() error {
	machine.mu.Lock()
	defer machine.mu.Unlock()
	if machine.state != StateNew {
		return machine.invalidStateLocked(MethodHello, StateNew)
	}
	machine.state = StateHello
	return nil
}

// AcceptPrepare advances HELLO to PREPARED after Core and the driver agree on
// the exact plan and permission subset.
func (machine *Machine) AcceptPrepare() error {
	machine.mu.Lock()
	defer machine.mu.Unlock()
	if machine.state != StateHello {
		return machine.invalidStateLocked(MethodPrepare, StateHello)
	}
	machine.state = StatePrepared
	return nil
}

// CheckCapabilities validates a capability query without changing state.
func (machine *Machine) CheckCapabilities() error {
	machine.mu.Lock()
	defer machine.mu.Unlock()
	if machine.state != StateHello && machine.state != StatePrepared {
		return protocolError(ErrorInvalidState, fmt.Sprintf("%s is invalid in %s", MethodCapabilities, machine.state), nil)
	}
	return nil
}

// BeginInvocation advances PREPARED to INVOKING and binds sequence and
// terminal validation to the invocation and attempt IDs.
func (machine *Machine) BeginInvocation(params InvokeParams) error {
	if err := params.Validate(); err != nil {
		return protocolError(ErrorInvalidRequest, "invalid invoke params", err)
	}
	machine.mu.Lock()
	defer machine.mu.Unlock()
	if machine.state != StatePrepared {
		return machine.invalidStateLocked(MethodInvoke, StatePrepared)
	}
	if _, exists := machine.completed[params.InvocationID]; exists {
		return protocolError(ErrorInvalidRequest, "invocation_id cannot be reused after terminal completion", nil)
	}
	machine.active = &activeInvocation{ActiveInvocation: ActiveInvocation{
		InvocationID: params.InvocationID,
		AttemptID:    params.AttemptID,
	}}
	machine.state = StateInvoking
	return nil
}

// RequestCancel records a cancellation request. It deliberately remains in
// INVOKING: cancel acknowledgement is not termination; only Complete may end
// the invocation.
func (machine *Machine) RequestCancel(params CancelParams) error {
	if err := params.Validate(); err != nil {
		return protocolError(ErrorInvalidRequest, "invalid cancel params", err)
	}
	machine.mu.Lock()
	defer machine.mu.Unlock()
	if machine.state != StateInvoking || machine.active == nil {
		return machine.invalidStateLocked(MethodCancel, StateInvoking)
	}
	if machine.active.InvocationID != params.InvocationID {
		return protocolError(ErrorInvalidRequest, "cancel invocation_id does not match the active invocation", nil)
	}
	machine.active.CancelRequested = true
	return nil
}

// Observe validates one driver.observation notification. Sequence values need
// not be contiguous, but each must be strictly greater than the previous one.
func (machine *Machine) Observe(params ObservationParams) error {
	if err := params.Validate(); err != nil {
		return protocolError(ErrorMalformedObservation, "invalid observation", err)
	}
	machine.mu.Lock()
	defer machine.mu.Unlock()
	if machine.state != StateInvoking || machine.active == nil {
		return machine.invalidStateLocked(MethodObservation, StateInvoking)
	}
	if machine.active.InvocationID != params.InvocationID || machine.active.AttemptID != params.AttemptID {
		return protocolError(ErrorMalformedObservation, "observation identity does not match the active invocation and attempt", nil)
	}
	if machine.active.HasObservation && params.Sequence <= machine.active.LastSequence {
		return protocolError(ErrorMalformedObservation, fmt.Sprintf("observation sequence %d is not greater than %d", params.Sequence, machine.active.LastSequence), nil)
	}
	machine.active.LastSequence = params.Sequence
	machine.active.HasObservation = true
	return nil
}

// Complete validates the unique terminal notification and advances INVOKING
// back to PREPARED. A completed invocation ID cannot be reused in this driver
// session.
func (machine *Machine) Complete(params CompletedParams) error {
	if err := params.Validate(); err != nil {
		return protocolError(ErrorMalformedObservation, "invalid completion", err)
	}
	machine.mu.Lock()
	defer machine.mu.Unlock()
	if machine.state != StateInvoking || machine.active == nil {
		return machine.invalidStateLocked(MethodCompleted, StateInvoking)
	}
	if machine.active.InvocationID != params.InvocationID || machine.active.AttemptID != params.AttemptID {
		return protocolError(ErrorMalformedObservation, "completion identity does not match the active invocation and attempt", nil)
	}
	if machine.active.HasObservation {
		if params.LastSequence == nil || *params.LastSequence != machine.active.LastSequence {
			return protocolError(ErrorMalformedObservation, "completion last_sequence does not match the last observation", nil)
		}
	} else if params.LastSequence != nil {
		return protocolError(ErrorMalformedObservation, "completion must omit last_sequence when no observation was emitted", nil)
	}
	machine.completed[params.InvocationID] = struct{}{}
	machine.active = nil
	machine.state = StatePrepared
	return nil
}

// Reset clears driver-owned prepared session data. It cannot run while an
// invocation is active and does not relax invocation-ID uniqueness.
func (machine *Machine) Reset() error {
	machine.mu.Lock()
	defer machine.mu.Unlock()
	if machine.state != StatePrepared {
		return machine.invalidStateLocked(MethodReset, StatePrepared)
	}
	return nil
}

// Shutdown advances PREPARED to the terminal SHUTDOWN state.
func (machine *Machine) Shutdown() error {
	machine.mu.Lock()
	defer machine.mu.Unlock()
	if machine.state != StatePrepared {
		return machine.invalidStateLocked(MethodShutdown, StatePrepared)
	}
	machine.state = StateShutdown
	return nil
}

// Apply validates and applies a decoded Driver request or notification. A
// response has no method correlation and must be handled by the caller's
// request table; applying one directly is rejected.
func (machine *Machine) Apply(message Message) error {
	kind, err := message.Kind()
	if err != nil {
		return err
	}
	if kind == MessageResponse {
		return protocolError(ErrorInvalidRequest, "cannot apply an uncorrelated JSON-RPC response to the driver state machine", nil)
	}

	switch message.Method {
	case MethodHello:
		var params HelloParams
		if err := DecodeParamsStrict(message.Params, &params); err != nil {
			return err
		}
		if err := params.Validate(); err != nil {
			return protocolError(ErrorInvalidRequest, "invalid hello params", err)
		}
		return machine.AcceptHello()
	case MethodPrepare:
		var params PrepareParams
		if err := DecodeParamsStrict(message.Params, &params); err != nil {
			return err
		}
		if err := params.Validate(); err != nil {
			return protocolError(ErrorInvalidRequest, "invalid prepare params", err)
		}
		return machine.AcceptPrepare()
	case MethodCapabilities:
		if err := decodeOptionalEmptyParams(message.Params); err != nil {
			return err
		}
		return machine.CheckCapabilities()
	case MethodInvoke:
		var params InvokeParams
		if err := DecodeParamsStrict(message.Params, &params); err != nil {
			return err
		}
		return machine.BeginInvocation(params)
	case MethodCancel:
		var params CancelParams
		if err := DecodeParamsStrict(message.Params, &params); err != nil {
			return err
		}
		return machine.RequestCancel(params)
	case MethodReset:
		if err := decodeOptionalEmptyParams(message.Params); err != nil {
			return err
		}
		return machine.Reset()
	case MethodShutdown:
		if err := decodeOptionalEmptyParams(message.Params); err != nil {
			return err
		}
		return machine.Shutdown()
	case MethodObservation:
		var params ObservationParams
		if err := DecodeParamsStrict(message.Params, &params); err != nil {
			return protocolError(ErrorMalformedObservation, "decode observation params", err)
		}
		return machine.Observe(params)
	case MethodCompleted:
		var params CompletedParams
		if err := DecodeParamsStrict(message.Params, &params); err != nil {
			return protocolError(ErrorMalformedObservation, "decode completion params", err)
		}
		return machine.Complete(params)
	default:
		return protocolError(ErrorInvalidRequest, fmt.Sprintf("unknown method %q", message.Method), nil)
	}
}

func (machine *Machine) invalidStateLocked(method Method, expected State) error {
	return protocolError(ErrorInvalidState, fmt.Sprintf("%s requires %s, current state is %s", method, expected, machine.state), nil)
}

func decodeOptionalEmptyParams(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var params struct{}
	return DecodeParamsStrict(raw, &params)
}
