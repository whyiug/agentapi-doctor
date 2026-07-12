package recorder

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const DefaultMaxSSEBufferBytes = 1 << 20
const maxSSEFieldsPerEvent = 1024

// ReadChunk is one transport read at an explicitly declared application
// capture layer. Its boundary is not an SSE logical-event boundary.
type ReadChunk struct {
	Sequence   uint64
	ByteOffset int64
	Data       []byte
}

type SSEField struct {
	Name  string
	Value string
}

// SSELogicalEvent is assembled from lines and retains the read chunks that
// contributed bytes. SourceChunkSequences is provenance, not event identity.
type SSELogicalEvent struct {
	Sequence             uint64
	EventOffset          int64
	Event                string
	Data                 string
	ID                   string
	RetryMillis          *int64
	Fields               []SSEField
	Issues               []string
	SourceChunkSequences []uint64
}

type StreamTail struct {
	BufferedBytes        int
	PendingFieldCount    int
	SourceChunkSequences []uint64
}

type SSEAssembler struct {
	maxBufferBytes int
	buffer         []byte

	nextChunkSequence uint64
	nextByteOffset    int64
	started           bool
	processedOffset   int64
	nextEventSequence uint64

	currentOffset int64
	currentBytes  int
	currentFields []SSEField
	currentChunks []uint64
}

func NewSSEAssembler(maxBufferBytes int) *SSEAssembler {
	if maxBufferBytes <= 0 {
		maxBufferBytes = DefaultMaxSSEBufferBytes
	}
	return &SSEAssembler{maxBufferBytes: maxBufferBytes, nextChunkSequence: 1, nextEventSequence: 1}
}

// Feed records one read boundary and emits zero or more logical SSE events.
// Arbitrary rechunking produces the same event fields while preserving
// different SourceChunkSequences.
func (assembler *SSEAssembler) Feed(chunk ReadChunk) ([]SSELogicalEvent, error) {
	if chunk.Sequence != assembler.nextChunkSequence {
		return nil, fmt.Errorf("read chunk sequence must be %d, got %d", assembler.nextChunkSequence, chunk.Sequence)
	}
	if chunk.ByteOffset < 0 || len(chunk.Data) == 0 {
		return nil, errors.New("read chunk requires nonnegative offset and nonempty data")
	}
	if !assembler.started {
		assembler.started = true
		assembler.nextByteOffset = chunk.ByteOffset
		assembler.processedOffset = chunk.ByteOffset
	}
	if chunk.ByteOffset != assembler.nextByteOffset {
		return nil, fmt.Errorf("read chunk byte offset must be %d, got %d", assembler.nextByteOffset, chunk.ByteOffset)
	}
	if len(assembler.buffer)+len(chunk.Data) > assembler.maxBufferBytes {
		return nil, fmt.Errorf("SSE buffered bytes exceed %d", assembler.maxBufferBytes)
	}
	assembler.buffer = append(assembler.buffer, chunk.Data...)
	assembler.nextChunkSequence++
	assembler.nextByteOffset += int64(len(chunk.Data))

	var events []SSELogicalEvent
	for {
		newline := bytes.IndexByte(assembler.buffer, '\n')
		if newline < 0 {
			if assembler.currentBytes+len(assembler.buffer) > assembler.maxBufferBytes {
				return nil, fmt.Errorf("SSE logical event exceeds %d bytes", assembler.maxBufferBytes)
			}
			assembler.addCurrentChunk(chunk.Sequence)
			break
		}
		assembler.addCurrentChunk(chunk.Sequence)
		lineStart := assembler.processedOffset
		line := append([]byte(nil), assembler.buffer[:newline]...)
		assembler.buffer = assembler.buffer[newline+1:]
		assembler.processedOffset += int64(newline + 1)
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if len(line) > 0 {
			assembler.currentBytes += len(line) + 1
			if assembler.currentBytes > assembler.maxBufferBytes {
				return nil, fmt.Errorf("SSE logical event exceeds %d bytes", assembler.maxBufferBytes)
			}
			if !bytes.HasPrefix(line, []byte(":")) && len(assembler.currentFields) >= maxSSEFieldsPerEvent {
				return nil, fmt.Errorf("SSE logical event exceeds %d fields", maxSSEFieldsPerEvent)
			}
		}
		event, emitted := assembler.consumeLine(string(line), lineStart)
		if emitted {
			events = append(events, event)
		}
	}
	return events, nil
}

// Finish reports an incomplete tail and deliberately does not dispatch it.
// A caller can therefore return inconclusive instead of inventing a terminal
// event at EOF.
func (assembler *SSEAssembler) Finish() StreamTail {
	return StreamTail{
		BufferedBytes:        len(assembler.buffer),
		PendingFieldCount:    len(assembler.currentFields),
		SourceChunkSequences: append([]uint64(nil), assembler.currentChunks...),
	}
}

func (assembler *SSEAssembler) consumeLine(line string, lineStart int64) (SSELogicalEvent, bool) {
	if line == "" {
		return assembler.dispatch()
	}
	if strings.HasPrefix(line, ":") {
		return SSELogicalEvent{}, false
	}
	if len(assembler.currentFields) == 0 {
		assembler.currentOffset = lineStart
	}
	name, value, found := strings.Cut(line, ":")
	if !found {
		value = ""
	} else if strings.HasPrefix(value, " ") {
		value = value[1:]
	}
	assembler.currentFields = append(assembler.currentFields, SSEField{Name: name, Value: value})
	return SSELogicalEvent{}, false
}

func (assembler *SSEAssembler) dispatch() (SSELogicalEvent, bool) {
	if len(assembler.currentFields) == 0 {
		assembler.currentBytes = 0
		assembler.currentChunks = nil
		return SSELogicalEvent{}, false
	}
	event := SSELogicalEvent{
		Sequence:             assembler.nextEventSequence,
		EventOffset:          assembler.currentOffset,
		Fields:               append([]SSEField(nil), assembler.currentFields...),
		SourceChunkSequences: append([]uint64(nil), assembler.currentChunks...),
	}
	var data []string
	for _, field := range assembler.currentFields {
		switch field.Name {
		case "event":
			event.Event = field.Value
		case "data":
			data = append(data, field.Value)
		case "id":
			if strings.ContainsRune(field.Value, '\x00') {
				event.Issues = append(event.Issues, "id_contains_nul")
			} else {
				event.ID = field.Value
			}
		case "retry":
			value, err := strconv.ParseInt(field.Value, 10, 64)
			if err != nil || value < 0 {
				event.Issues = append(event.Issues, "invalid_retry")
			} else {
				event.RetryMillis = &value
			}
		}
	}
	event.Data = strings.Join(data, "\n")
	assembler.nextEventSequence++
	assembler.currentBytes = 0
	assembler.currentFields = nil
	assembler.currentChunks = nil
	return event, true
}

func (assembler *SSEAssembler) addCurrentChunk(sequence uint64) {
	if len(assembler.currentChunks) == 0 || assembler.currentChunks[len(assembler.currentChunks)-1] != sequence {
		assembler.currentChunks = append(assembler.currentChunks, sequence)
	}
}
