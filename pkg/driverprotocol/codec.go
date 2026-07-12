package driverprotocol

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	publicschema "github.com/whyiug/agentapi-doctor/pkg/schema"
)

var (
	ErrEmptyControlFrame     = errors.New("empty driver control frame")
	ErrMultilineControlFrame = errors.New("driver control frame must be one NDJSON line")
	ErrControlFrameTooLarge  = errors.New("driver control frame exceeds 1 MiB")
	ErrDataFrameTooLarge     = errors.New("driver data frame exceeds 256 KiB")
)

// DecodeControlFrame decodes one complete NDJSON line. A single trailing LF
// or CRLF is accepted; embedded physical newlines are rejected. Duplicate JSON
// members, concatenated values, invalid UTF-8, unknown envelope fields, and
// unknown Driver RPC methods fail closed.
func DecodeControlFrame(line []byte) (Message, error) {
	frame, err := stripNDJSONLineEnding(line)
	if err != nil {
		return Message{}, err
	}
	if err := ValidateControlFrameSize(len(frame)); err != nil {
		return Message{}, err
	}
	canonical, err := publicschema.CanonicalizeJSON(frame)
	if err != nil {
		return Message{}, protocolError(ErrorInvalidRequest, "control frame is not strict JSON", err)
	}
	if len(canonical) == 0 || canonical[0] != '{' {
		return Message{}, protocolError(ErrorInvalidRequest, "control frame must be a JSON object", nil)
	}

	var message Message
	if err := decodeStrict(canonical, &message); err != nil {
		return Message{}, protocolError(ErrorInvalidRequest, "decode control frame", err)
	}
	if _, err := message.Kind(); err != nil {
		return Message{}, err
	}
	if err := validateMethodPayload(message); err != nil {
		return Message{}, err
	}
	return message, nil
}

// EncodeControlFrame validates and RFC-8785-canonicalizes a message, then
// appends exactly one LF for NDJSON transport.
func EncodeControlFrame(message Message) ([]byte, error) {
	if _, err := message.Kind(); err != nil {
		return nil, err
	}
	if err := validateMethodPayload(message); err != nil {
		return nil, err
	}
	canonical, err := publicschema.CanonicalMarshal(message)
	if err != nil {
		return nil, protocolError(ErrorInvalidRequest, "encode control frame", err)
	}
	if err := ValidateControlFrameSize(len(canonical)); err != nil {
		return nil, err
	}
	return append(canonical, '\n'), nil
}

// Decoder reads strict NDJSON control frames without allowing an unbounded
// line allocation. After an oversized line, it drains through the delimiter
// so a caller may continue with the next frame.
type Decoder struct {
	reader *bufio.Reader
}

// NewDecoder creates an NDJSON control decoder.
func NewDecoder(reader io.Reader) *Decoder {
	return &Decoder{reader: bufio.NewReaderSize(reader, 64<<10)}
}

// Decode reads one control message. A final line without LF is accepted.
func (decoder *Decoder) Decode() (Message, error) {
	if decoder == nil || decoder.reader == nil {
		return Message{}, protocolError(ErrorInvalidRequest, "control decoder has no reader", nil)
	}
	line := make([]byte, 0, 64<<10)
	for {
		fragment, err := decoder.reader.ReadSlice('\n')
		if len(line)+len(fragment) > MaxControlFrameBytes+2 {
			if err == bufio.ErrBufferFull {
				for err == bufio.ErrBufferFull {
					_, err = decoder.reader.ReadSlice('\n')
				}
			}
			return Message{}, protocolError(ErrorBudgetExceeded, ErrControlFrameTooLarge.Error(), ErrControlFrameTooLarge)
		}
		line = append(line, fragment...)
		switch err {
		case nil:
			return DecodeControlFrame(line)
		case bufio.ErrBufferFull:
			continue
		case io.EOF:
			if len(line) == 0 {
				return Message{}, io.EOF
			}
			return DecodeControlFrame(line)
		default:
			return Message{}, fmt.Errorf("read driver control frame: %w", err)
		}
	}
}

// Encoder writes canonical NDJSON control frames.
type Encoder struct {
	writer io.Writer
}

// NewEncoder creates an NDJSON control encoder.
func NewEncoder(writer io.Writer) *Encoder { return &Encoder{writer: writer} }

// Encode writes exactly one complete control frame.
func (encoder *Encoder) Encode(message Message) error {
	if encoder == nil || encoder.writer == nil {
		return protocolError(ErrorInvalidRequest, "control encoder has no writer", nil)
	}
	frame, err := EncodeControlFrame(message)
	if err != nil {
		return err
	}
	written, err := encoder.writer.Write(frame)
	if err != nil {
		return fmt.Errorf("write driver control frame: %w", err)
	}
	if written != len(frame) {
		return io.ErrShortWrite
	}
	return nil
}

// DecodeParamsStrict decodes method params or a result into a public typed
// contract. It rejects duplicate and unknown fields and requires one JSON
// value. Callers should pass a pointer to the destination.
func DecodeParamsStrict(raw json.RawMessage, destination any) error {
	if len(raw) == 0 {
		return protocolError(ErrorInvalidRequest, "params are required", nil)
	}
	if destination == nil {
		return protocolError(ErrorInvalidRequest, "params destination is nil", nil)
	}
	canonical, err := publicschema.CanonicalizeJSON(raw)
	if err != nil {
		return protocolError(ErrorInvalidRequest, "params are not strict JSON", err)
	}
	if err := decodeStrict(canonical, destination); err != nil {
		return protocolError(ErrorInvalidRequest, "decode params", err)
	}
	return nil
}

// ValidateControlFrameSize applies the fixed v1 control-plane bound.
func ValidateControlFrameSize(size int) error {
	if size < 0 {
		return protocolError(ErrorInvalidRequest, "negative control frame size", nil)
	}
	if size > MaxControlFrameBytes {
		return protocolError(ErrorBudgetExceeded, ErrControlFrameTooLarge.Error(), ErrControlFrameTooLarge)
	}
	return nil
}

// ValidateDataFrameSize applies the default companion data-plane frame bound.
// A negotiated lower limit must be checked by the caller as well.
func ValidateDataFrameSize(size int) error {
	if size < 0 {
		return protocolError(ErrorInvalidRequest, "negative data frame size", nil)
	}
	if size > DefaultMaxDataFrameBytes {
		return protocolError(ErrorBudgetExceeded, ErrDataFrameTooLarge.Error(), ErrDataFrameTooLarge)
	}
	return nil
}

func stripNDJSONLineEnding(line []byte) ([]byte, error) {
	if len(line) == 0 {
		return nil, protocolError(ErrorInvalidRequest, ErrEmptyControlFrame.Error(), ErrEmptyControlFrame)
	}
	frame := line
	if frame[len(frame)-1] == '\n' {
		frame = frame[:len(frame)-1]
		if len(frame) != 0 && frame[len(frame)-1] == '\r' {
			frame = frame[:len(frame)-1]
		}
	}
	if len(frame) == 0 {
		return nil, protocolError(ErrorInvalidRequest, ErrEmptyControlFrame.Error(), ErrEmptyControlFrame)
	}
	if bytes.IndexByte(frame, '\n') >= 0 || bytes.IndexByte(frame, '\r') >= 0 {
		return nil, protocolError(ErrorInvalidRequest, ErrMultilineControlFrame.Error(), ErrMultilineControlFrame)
	}
	return frame, nil
}

func decodeStrict(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := ensureDecoderEOF(decoder); err != nil {
		return err
	}
	return nil
}

func ensureDecoderEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("unexpected trailing JSON value")
		}
		return fmt.Errorf("read trailing JSON: %w", err)
	}
	return nil
}

func validateParamsShape(raw json.RawMessage) error {
	canonical, err := publicschema.CanonicalizeJSON(raw)
	if err != nil {
		return err
	}
	if len(canonical) == 0 || (canonical[0] != '{' && canonical[0] != '[') {
		return errors.New("params are not an object or array")
	}
	return nil
}

func validateRequestID(raw json.RawMessage) error {
	canonical, err := publicschema.CanonicalizeJSON(raw)
	if err != nil {
		return err
	}
	if bytes.Equal(canonical, []byte("null")) {
		return errors.New("null request ID is not permitted")
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	switch typed := value.(type) {
	case string:
		return nil
	case json.Number:
		if strings.ContainsAny(typed.String(), ".eE") {
			return errors.New("fractional or exponent request ID is not permitted")
		}
		return nil
	default:
		return fmt.Errorf("request ID must be a string or integer, got %T", value)
	}
}

func validateResponseID(raw json.RawMessage) error {
	return validateRequestID(raw)
}

func validateMethodPayload(message Message) error {
	if message.Method == "" {
		return nil
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
	case MethodPrepare:
		var params PrepareParams
		if err := DecodeParamsStrict(message.Params, &params); err != nil {
			return err
		}
		if err := params.Validate(); err != nil {
			return protocolError(ErrorInvalidRequest, "invalid prepare params", err)
		}
	case MethodCapabilities, MethodReset, MethodShutdown:
		if err := decodeOptionalEmptyParams(message.Params); err != nil {
			return err
		}
	case MethodInvoke:
		var params InvokeParams
		if err := DecodeParamsStrict(message.Params, &params); err != nil {
			return err
		}
		if err := params.Validate(); err != nil {
			return protocolError(ErrorInvalidRequest, "invalid invoke params", err)
		}
	case MethodCancel:
		var params CancelParams
		if err := DecodeParamsStrict(message.Params, &params); err != nil {
			return err
		}
		if err := params.Validate(); err != nil {
			return protocolError(ErrorInvalidRequest, "invalid cancel params", err)
		}
	case MethodObservation:
		var params ObservationParams
		if err := DecodeParamsStrict(message.Params, &params); err != nil {
			return protocolError(ErrorMalformedObservation, "decode observation params", err)
		}
		if err := params.Validate(); err != nil {
			return protocolError(ErrorMalformedObservation, "invalid observation params", err)
		}
	case MethodCompleted:
		var params CompletedParams
		if err := DecodeParamsStrict(message.Params, &params); err != nil {
			return protocolError(ErrorMalformedObservation, "decode completion params", err)
		}
		if err := params.Validate(); err != nil {
			return protocolError(ErrorMalformedObservation, "invalid completion params", err)
		}
	}
	return nil
}
