package driverprotocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	publicschema "github.com/whyiug/agentapi-doctor/pkg/schema"
)

const (
	// JSONRPCVersion is the only JSON-RPC envelope version accepted by v1.
	JSONRPCVersion = "2.0"

	// MaxControlFrameBytes bounds a JSON value before the NDJSON line ending.
	MaxControlFrameBytes = 1 << 20
	// DefaultMaxDataFrameBytes bounds a payload on the companion data plane.
	DefaultMaxDataFrameBytes = 256 << 10
)

// Method is a stable Driver RPC method or notification name.
type Method string

const (
	MethodHello        Method = "driver.hello"
	MethodPrepare      Method = "driver.prepare"
	MethodCapabilities Method = "driver.capabilities"
	MethodInvoke       Method = "driver.invoke"
	MethodCancel       Method = "driver.cancel"
	MethodReset        Method = "driver.reset"
	MethodShutdown     Method = "driver.shutdown"
	MethodObservation  Method = "driver.observation"
	MethodCompleted    Method = "driver.completed"
)

var requestMethods = map[Method]struct{}{
	MethodHello:        {},
	MethodPrepare:      {},
	MethodCapabilities: {},
	MethodInvoke:       {},
	MethodCancel:       {},
	MethodReset:        {},
	MethodShutdown:     {},
}

var notificationMethods = map[Method]struct{}{
	MethodObservation: {},
	MethodCompleted:   {},
}

func (method Method) validate() error {
	if _, ok := requestMethods[method]; ok {
		return nil
	}
	if _, ok := notificationMethods[method]; ok {
		return nil
	}
	return fmt.Errorf("unknown driver method %q", method)
}

// MessageKind distinguishes JSON-RPC requests, notifications, and responses.
type MessageKind uint8

const (
	MessageInvalid MessageKind = iota
	MessageRequest
	MessageNotification
	MessageResponse
)

// Message is one strict JSON-RPC 2.0 control frame. ID is retained as raw JSON
// so string and numeric IDs round-trip without lossy conversion. An absent ID
// is a notification; an explicit JSON null is still an ID and is rejected for
// requests because null cannot be correlated safely.
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  Method          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// Kind validates the envelope shape and returns its JSON-RPC kind.
func (message Message) Kind() (MessageKind, error) {
	if message.JSONRPC != JSONRPCVersion {
		return MessageInvalid, protocolError(ErrorUnsupportedRPCVersion, "jsonrpc must be 2.0", nil)
	}

	hasID := len(message.ID) != 0
	hasMethod := message.Method != ""
	hasParams := len(message.Params) != 0
	hasResult := len(message.Result) != 0
	hasError := message.Error != nil

	if hasMethod {
		if err := message.Method.validate(); err != nil {
			return MessageInvalid, protocolError(ErrorInvalidRequest, err.Error(), err)
		}
		if hasResult || hasError {
			return MessageInvalid, protocolError(ErrorInvalidRequest, "method message cannot contain result or error", nil)
		}
		if hasParams {
			if err := validateParamsShape(message.Params); err != nil {
				return MessageInvalid, protocolError(ErrorInvalidRequest, "params must be an object or array", err)
			}
		}
		if _, notification := notificationMethods[message.Method]; notification {
			if hasID {
				return MessageInvalid, protocolError(ErrorInvalidRequest, "driver notification must not contain id", nil)
			}
			return MessageNotification, nil
		}
		if !hasID {
			return MessageInvalid, protocolError(ErrorInvalidRequest, "driver request must contain id", nil)
		}
		if err := validateRequestID(message.ID); err != nil {
			return MessageInvalid, protocolError(ErrorInvalidRequest, "invalid request id", err)
		}
		return MessageRequest, nil
	}

	if hasParams {
		return MessageInvalid, protocolError(ErrorInvalidRequest, "response cannot contain params", nil)
	}
	if !hasID || hasResult == hasError {
		return MessageInvalid, protocolError(ErrorInvalidRequest, "response requires id and exactly one of result or error", nil)
	}
	if err := validateResponseID(message.ID); err != nil {
		return MessageInvalid, protocolError(ErrorInvalidRequest, "invalid response id", err)
	}
	if hasError {
		if err := message.Error.Validate(); err != nil {
			return MessageInvalid, err
		}
	}
	return MessageResponse, nil
}

// ErrorClass is the stable machine-readable failure taxonomy. It is separate
// from the numeric JSON-RPC error code.
type ErrorClass string

const (
	ErrorUnsupportedRPCVersion ErrorClass = "unsupported_rpc_version"
	ErrorInvalidState          ErrorClass = "invalid_state"
	ErrorInvalidRequest        ErrorClass = "invalid_request"
	ErrorPermissionDenied      ErrorClass = "permission_denied"
	ErrorBudgetExceeded        ErrorClass = "budget_exceeded"
	ErrorCapabilityMismatch    ErrorClass = "capability_mismatch"
	ErrorDriverInternal        ErrorClass = "driver_internal"
	ErrorCancellationTimeout   ErrorClass = "cancellation_timeout"
	ErrorMalformedObservation  ErrorClass = "malformed_observation"
	ErrorArtifactMismatch      ErrorClass = "artifact_mismatch"
)

var stableErrorClasses = map[ErrorClass]struct{}{
	ErrorUnsupportedRPCVersion: {},
	ErrorInvalidState:          {},
	ErrorInvalidRequest:        {},
	ErrorPermissionDenied:      {},
	ErrorBudgetExceeded:        {},
	ErrorCapabilityMismatch:    {},
	ErrorDriverInternal:        {},
	ErrorCancellationTimeout:   {},
	ErrorMalformedObservation:  {},
	ErrorArtifactMismatch:      {},
}

// ErrorData carries the stable class and optional bounded structured details.
// Details remain application data; core error fields are strict.
type ErrorData struct {
	Class   ErrorClass      `json:"class"`
	Details json.RawMessage `json:"details,omitempty"`
}

// RPCError is the JSON-RPC error object.
type RPCError struct {
	Code    int        `json:"code"`
	Message string     `json:"message"`
	Data    *ErrorData `json:"data"`
}

// Validate checks the stable class and the JSON-RPC error body.
func (rpcError RPCError) Validate() error {
	if rpcError.Message == "" {
		return protocolError(ErrorInvalidRequest, "RPC error message is required", nil)
	}
	if rpcError.Data == nil {
		return protocolError(ErrorInvalidRequest, "RPC error data with a stable class is required", nil)
	}
	if _, ok := stableErrorClasses[rpcError.Data.Class]; !ok {
		return protocolError(ErrorInvalidRequest, fmt.Sprintf("unknown RPC error class %q", rpcError.Data.Class), nil)
	}
	if len(rpcError.Data.Details) != 0 {
		if _, err := publicschema.CanonicalizeJSON(rpcError.Data.Details); err != nil {
			return protocolError(ErrorInvalidRequest, "RPC error details are not strict JSON", err)
		}
	}
	return nil
}

// ProtocolError is returned by codec and state-machine validation. Class is
// stable and suitable for a JSON-RPC ErrorData.Class value.
type ProtocolError struct {
	Class   ErrorClass
	Message string
	Cause   error
}

func (err *ProtocolError) Error() string {
	if err == nil {
		return "<nil>"
	}
	return string(err.Class) + ": " + err.Message
}

func (err *ProtocolError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Cause
}

func protocolError(class ErrorClass, message string, cause error) *ProtocolError {
	return &ProtocolError{Class: class, Message: message, Cause: cause}
}

// ErrorClassOf extracts a stable class from a protocol error.
func ErrorClassOf(err error) (ErrorClass, bool) {
	var target *ProtocolError
	if !errors.As(err, &target) {
		return "", false
	}
	return target.Class, true
}

// VersionRange is the inclusive Driver RPC version range offered at hello.
type VersionRange struct {
	Minimum string `json:"minimum"`
	Maximum string `json:"maximum"`
}

func (version VersionRange) validate() error {
	if version.Minimum == "" || version.Maximum == "" {
		return errors.New("minimum and maximum RPC versions are required")
	}
	return nil
}

// DriverIdentity pins all executable and client inputs relevant to an
// observation. Optional SDK/client fields are omitted for the built-in raw
// driver.
type DriverIdentity struct {
	Name           string              `json:"name"`
	Version        string              `json:"version"`
	SDKName        string              `json:"sdk_name,omitempty"`
	SDKVersion     string              `json:"sdk_version,omitempty"`
	ClientName     string              `json:"client_name,omitempty"`
	ClientVersion  string              `json:"client_version,omitempty"`
	RuntimeName    string              `json:"runtime_name"`
	RuntimeVersion string              `json:"runtime_version"`
	OS             string              `json:"os"`
	Architecture   string              `json:"architecture"`
	ArtifactDigest publicschema.Digest `json:"artifact_digest"`
	LockfileDigest publicschema.Digest `json:"lockfile_digest,omitempty"`
}

func (identity DriverIdentity) validate() error {
	for name, value := range map[string]string{
		"name": identity.Name, "version": identity.Version,
		"runtime_name": identity.RuntimeName, "runtime_version": identity.RuntimeVersion,
		"os": identity.OS, "architecture": identity.Architecture,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("driver identity %s is required", name)
		}
	}
	if err := identity.ArtifactDigest.Validate(); err != nil {
		return fmt.Errorf("driver artifact digest: %w", err)
	}
	if identity.LockfileDigest != "" {
		if err := identity.LockfileDigest.Validate(); err != nil {
			return fmt.Errorf("driver lockfile digest: %w", err)
		}
	}
	if (identity.SDKName == "") != (identity.SDKVersion == "") {
		return errors.New("SDK name and version must be provided together")
	}
	if (identity.ClientName == "") != (identity.ClientVersion == "") {
		return errors.New("client name and version must be provided together")
	}
	return nil
}

// Capabilities declares what the driver can execute; it is not evidence that
// the target supports the same capability.
type Capabilities struct {
	Protocols      []string `json:"protocols"`
	Operations     []string `json:"operations"`
	Streaming      bool     `json:"streaming"`
	Cancellation   bool     `json:"cancellation"`
	RetryObserved  bool     `json:"retry_observed"`
	Concurrency    bool     `json:"concurrency"`
	MaxConcurrency uint32   `json:"max_concurrency"`
}

// Permission names a capability-scoped sandbox permission.
type Permission string

// HelloParams contains the Core's supported Driver API range.
type HelloParams struct {
	CoreVersionRange VersionRange `json:"core_version_range"`
}

func (params HelloParams) Validate() error { return params.CoreVersionRange.validate() }

// HelloResult binds the driver identity, API range, capabilities, and
// requested permissions returned by the handshake.
type HelloResult struct {
	DriverVersionRange   VersionRange   `json:"driver_version_range"`
	Identity             DriverIdentity `json:"identity"`
	Capabilities         Capabilities   `json:"capabilities"`
	RequestedPermissions []Permission   `json:"requested_permissions"`
}

func (result HelloResult) Validate() error {
	if err := result.DriverVersionRange.validate(); err != nil {
		return err
	}
	return result.Identity.validate()
}

// CapabilitiesParams is intentionally empty. A later version must add fields
// through a separately versioned contract rather than accepting typos.
type CapabilitiesParams struct{}

// CapabilitiesResult returns the current prepared driver's capabilities.
type CapabilitiesResult struct {
	Capabilities Capabilities `json:"capabilities"`
}

// PrepareParams pins the approved plan and the subset of permissions offered
// to the driver. CapabilityToken is ephemeral and must never be persisted.
type PrepareParams struct {
	ResolvedPlanDigest  publicschema.Digest      `json:"resolved_plan_digest"`
	CapabilityToken     string                   `json:"capability_token"`
	FixtureRefs         []publicschema.ObjectRef `json:"fixture_refs,omitempty"`
	ApprovedPermissions []Permission             `json:"approved_permissions"`
}

func (params PrepareParams) Validate() error {
	if err := params.ResolvedPlanDigest.Validate(); err != nil {
		return fmt.Errorf("resolved plan digest: %w", err)
	}
	if params.CapabilityToken == "" {
		return errors.New("capability token is required")
	}
	for index, ref := range params.FixtureRefs {
		if err := ref.Validate(); err != nil {
			return fmt.Errorf("fixture_refs[%d]: %w", index, err)
		}
	}
	return nil
}

// PrepareResult records the exact permission subset accepted by the driver.
type PrepareResult struct {
	AcceptedPermissions []Permission `json:"accepted_permissions"`
}

// ExactInputHandle describes an invocation-scoped input channel. The handle
// value is operational state and must not be copied to evidence or reports.
type ExactInputHandle struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

func (handle ExactInputHandle) validate() error {
	switch handle.Kind {
	case "pipe", "socket", "memfd":
	default:
		return fmt.Errorf("unsupported exact input handle kind %q", handle.Kind)
	}
	if handle.Value == "" {
		return errors.New("exact input handle value is required")
	}
	return nil
}

// InvokeParams starts one invocation. Base v1 state-machine validation is
// serial; negotiated concurrency requires a higher-level dispatcher with one
// Machine per active invocation.
type InvokeParams struct {
	InvocationID publicschema.InstanceID `json:"invocation_id"`
	AttemptID    publicschema.InstanceID `json:"attempt_id"`
	Operation    string                  `json:"operation"`
	Input        ExactInputHandle        `json:"ephemeral_exact_input_handle"`
}

func (params InvokeParams) Validate() error {
	if err := params.InvocationID.Validate(); err != nil {
		return fmt.Errorf("invocation_id: %w", err)
	}
	if err := params.AttemptID.Validate(); err != nil {
		return fmt.Errorf("attempt_id: %w", err)
	}
	if params.Operation == "" {
		return errors.New("operation is required")
	}
	return params.Input.validate()
}

// CancelParams asks the driver to begin cancellation. DeadlineMillis is a
// relative time budget supplied by Core; an acknowledgement is not terminal.
type CancelParams struct {
	InvocationID   publicschema.InstanceID `json:"invocation_id"`
	Reason         string                  `json:"reason"`
	DeadlineMillis uint64                  `json:"deadline_millis"`
}

func (params CancelParams) Validate() error {
	if err := params.InvocationID.Validate(); err != nil {
		return fmt.Errorf("invocation_id: %w", err)
	}
	if params.Reason == "" {
		return errors.New("cancel reason is required")
	}
	if params.DeadlineMillis == 0 {
		return errors.New("cancel deadline_millis must be greater than zero")
	}
	return nil
}

// CancelResult acknowledges receipt only. Termination is represented solely
// by driver.completed.
type CancelResult struct {
	Acknowledged bool `json:"acknowledged"`
}

type ResetParams struct{}
type ResetResult struct{}
type ShutdownParams struct{}
type ShutdownResult struct{}

// CompanionStreamRef identifies a negotiated data-plane stream. It is not a
// CAS reference.
type CompanionStreamRef struct {
	StreamID string `json:"stream_id"`
}

// ObservationParams is the only semantic observation notification.
type ObservationParams struct {
	InvocationID publicschema.InstanceID `json:"invocation_id"`
	AttemptID    publicschema.InstanceID `json:"attempt_id"`
	Sequence     uint64                  `json:"sequence"`
	Kind         string                  `json:"kind"`
	MonotonicNS  uint64                  `json:"monotonic_ns"`
	Payload      json.RawMessage         `json:"payload,omitempty"`
	DataStream   *CompanionStreamRef     `json:"data_stream,omitempty"`
}

func (params ObservationParams) Validate() error {
	if err := params.InvocationID.Validate(); err != nil {
		return fmt.Errorf("invocation_id: %w", err)
	}
	if err := params.AttemptID.Validate(); err != nil {
		return fmt.Errorf("attempt_id: %w", err)
	}
	if params.Kind == "" {
		return errors.New("observation kind is required")
	}
	if len(params.Payload) != 0 && params.DataStream != nil {
		return errors.New("observation cannot contain both inline payload and data_stream")
	}
	if len(params.Payload) != 0 {
		if _, err := publicschema.CanonicalizeJSON(params.Payload); err != nil {
			return fmt.Errorf("observation payload: %w", err)
		}
	}
	if params.DataStream != nil && params.DataStream.StreamID == "" {
		return errors.New("data stream ID is required")
	}
	return nil
}

// TerminalStatus is emitted exactly once for an invocation.
type TerminalStatus string

const (
	TerminalCompleted TerminalStatus = "completed"
	TerminalCancelled TerminalStatus = "cancelled"
	TerminalErrored   TerminalStatus = "errored"
)

// CompletedParams terminates an invocation. LastSequence is nil when no
// observation was emitted and otherwise must equal the last observed value.
type CompletedParams struct {
	InvocationID  publicschema.InstanceID `json:"invocation_id"`
	AttemptID     publicschema.InstanceID `json:"attempt_id"`
	Status        TerminalStatus          `json:"status"`
	LastSequence  *uint64                 `json:"last_sequence,omitempty"`
	SummaryDigest publicschema.Digest     `json:"summary_digest"`
}

func (params CompletedParams) Validate() error {
	if err := params.InvocationID.Validate(); err != nil {
		return fmt.Errorf("invocation_id: %w", err)
	}
	if err := params.AttemptID.Validate(); err != nil {
		return fmt.Errorf("attempt_id: %w", err)
	}
	switch params.Status {
	case TerminalCompleted, TerminalCancelled, TerminalErrored:
	default:
		return fmt.Errorf("unknown terminal status %q", params.Status)
	}
	if err := params.SummaryDigest.Validate(); err != nil {
		return fmt.Errorf("summary digest: %w", err)
	}
	return nil
}

// DataFrameHeader precedes one companion-pipe payload.
type DataFrameHeader struct {
	InvocationID publicschema.InstanceID `json:"invocation_id"`
	AttemptID    publicschema.InstanceID `json:"attempt_id"`
	StreamID     string                  `json:"stream_id"`
	Sequence     uint64                  `json:"sequence"`
	Length       uint32                  `json:"length"`
	Final        bool                    `json:"final"`
}

// Validate checks identity and the default data-frame bound.
func (header DataFrameHeader) Validate() error {
	if err := header.InvocationID.Validate(); err != nil {
		return fmt.Errorf("invocation_id: %w", err)
	}
	if err := header.AttemptID.Validate(); err != nil {
		return fmt.Errorf("attempt_id: %w", err)
	}
	if header.StreamID == "" {
		return errors.New("stream_id is required")
	}
	return ValidateDataFrameSize(int(header.Length))
}
