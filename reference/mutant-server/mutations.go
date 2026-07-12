package mutantserver

import (
	"errors"
	"fmt"
	"slices"

	referenceserver "github.com/whyiug/agentapi-doctor/reference/server"
)

func applyMutation(id ID, exchange *referenceserver.Exchange) error {
	if exchange == nil {
		return errors.New("exchange is required")
	}
	switch id {
	case ArgumentsObjectInsteadOfString:
		return argumentsObject(exchange)
	case MissingOutputIndex:
		return missingOutputIndex(exchange)
	case DuplicateOutputIndex:
		return duplicateOutputIndex(exchange)
	case DroppedStreamingToolCall:
		return dropStreamingToolCall(exchange)
	case InvalidFinishReason:
		return invalidFinishReason(exchange)
	case MissingTerminalEvent:
		return missingTerminal(exchange)
	case DuplicateTerminalEvent:
		return duplicateTerminal(exchange)
	case ToolCallIDChanged:
		return changeToolCallID(exchange)
	case UnknownEventCrashesClient:
		return injectUnknownEvent(exchange)
	case UnclosedReasoningBlock:
		return unclosedReasoning(exchange)
	case UsageInconsistent:
		return inconsistentUsage(exchange)
	case TruncatedUTF8:
		return truncatedUTF8(exchange)
	default:
		return fmt.Errorf("unknown mutation ID %q", id)
	}
}

func argumentsObject(exchange *referenceserver.Exchange) error {
	if exchange.Scenario != referenceserver.ScenarioTool {
		return errors.New("tool scenario is required")
	}
	arguments := map[string]any{"text": "fixture"}
	if !exchange.Streaming {
		switch exchange.Protocol {
		case referenceserver.ProtocolOpenAIChat:
			choice := firstMap(exchange.JSON["choices"])
			message := mapValue(choice, "message")
			call := firstMap(message["tool_calls"])
			mapValue(call, "function")["arguments"] = arguments
			return nil
		case referenceserver.ProtocolOpenAIResponses:
			firstMap(exchange.JSON["output"])["arguments"] = arguments
			return nil
		default:
			return errors.New("mutation does not apply to native object arguments")
		}
	}
	for _, event := range exchange.Events {
		data, ok := event.Data.(map[string]any)
		if !ok {
			continue
		}
		if exchange.Protocol == referenceserver.ProtocolOpenAIResponses && data["type"] == "response.function_call_arguments.done" {
			data["arguments"] = arguments
			return nil
		}
		if exchange.Protocol == referenceserver.ProtocolOpenAIChat {
			choice := firstMap(data["choices"])
			delta := mapValue(choice, "delta")
			calls, _ := delta["tool_calls"].([]any)
			if len(calls) > 0 {
				function := mapValue(calls[len(calls)-1].(map[string]any), "function")
				if function["arguments"] != "" {
					function["arguments"] = arguments
					return nil
				}
			}
		}
	}
	return errors.New("function arguments were not found")
}

func missingOutputIndex(exchange *referenceserver.Exchange) error {
	if exchange.Protocol != referenceserver.ProtocolOpenAIResponses || !exchange.Streaming {
		return errors.New("responses streaming scenario is required")
	}
	for _, event := range exchange.Events {
		data, ok := event.Data.(map[string]any)
		if ok {
			if _, exists := data["output_index"]; exists {
				delete(data, "output_index")
				return nil
			}
		}
	}
	return errors.New("output_index was not found")
}

func duplicateOutputIndex(exchange *referenceserver.Exchange) error {
	if exchange.Protocol != referenceserver.ProtocolOpenAIResponses || !exchange.Streaming {
		return errors.New("responses streaming scenario is required")
	}
	for index, event := range exchange.Events {
		data, ok := event.Data.(map[string]any)
		if !ok || data["type"] != "response.output_item.added" {
			continue
		}
		duplicate := cloneMap(data)
		item := cloneMap(mapValue(duplicate, "item"))
		item["id"] = "item_duplicate_index"
		duplicate["item"] = item
		copyEvent := referenceserver.SSEEvent{Event: event.Event, Data: duplicate}
		insertEvents(exchange, index+1, copyEvent)
		return nil
	}
	return errors.New("output item event was not found")
}

func dropStreamingToolCall(exchange *referenceserver.Exchange) error {
	if !exchange.Streaming || exchange.Scenario != referenceserver.ScenarioTool {
		return errors.New("streaming tool scenario is required")
	}
	filtered := exchange.Events[:0]
	dropped := false
	for _, event := range exchange.Events {
		if isToolEvent(exchange.Protocol, event) {
			dropped = true
			continue
		}
		filtered = append(filtered, event)
	}
	if !dropped {
		return errors.New("tool event was not found")
	}
	exchange.Events = filtered
	return nil
}

func isToolEvent(protocol referenceserver.Protocol, event referenceserver.SSEEvent) bool {
	data, _ := event.Data.(map[string]any)
	switch protocol {
	case referenceserver.ProtocolOpenAIChat:
		choice := firstMap(data["choices"])
		delta := mapValue(choice, "delta")
		_, exists := delta["tool_calls"]
		return exists
	case referenceserver.ProtocolOpenAIResponses:
		typeName, _ := data["type"].(string)
		if typeName == "response.function_call_arguments.delta" || typeName == "response.function_call_arguments.done" {
			return true
		}
		if typeName == "response.output_item.added" || typeName == "response.output_item.done" {
			item, _ := data["item"].(map[string]any)
			return item["type"] == "function_call"
		}
	case referenceserver.ProtocolAnthropic:
		return event.Event == "content_block_start" || event.Event == "content_block_delta" || event.Event == "content_block_stop"
	}
	return false
}

func invalidFinishReason(exchange *referenceserver.Exchange) error {
	const invalid = "fixture_invalid_reason"
	if !exchange.Streaming {
		switch exchange.Protocol {
		case referenceserver.ProtocolOpenAIChat:
			firstMap(exchange.JSON["choices"])["finish_reason"] = invalid
		case referenceserver.ProtocolOpenAIResponses:
			exchange.JSON["status"] = invalid
		case referenceserver.ProtocolAnthropic:
			exchange.JSON["stop_reason"] = invalid
		}
		return nil
	}
	for _, event := range exchange.Events {
		data, _ := event.Data.(map[string]any)
		switch exchange.Protocol {
		case referenceserver.ProtocolOpenAIChat:
			choice := firstMap(data["choices"])
			if reason, exists := choice["finish_reason"]; exists && reason != nil {
				choice["finish_reason"] = invalid
				return nil
			}
		case referenceserver.ProtocolOpenAIResponses:
			if data["type"] == "response.completed" {
				mapValue(data, "response")["status"] = invalid
				return nil
			}
		case referenceserver.ProtocolAnthropic:
			if event.Event == "message_delta" {
				mapValue(data, "delta")["stop_reason"] = invalid
				return nil
			}
		}
	}
	return errors.New("terminal reason was not found")
}

func missingTerminal(exchange *referenceserver.Exchange) error {
	if !exchange.Streaming {
		return errors.New("streaming scenario is required")
	}
	filtered := exchange.Events[:0]
	found := false
	for _, event := range exchange.Events {
		if event.Terminal {
			found = true
			continue
		}
		filtered = append(filtered, event)
	}
	if !found {
		return errors.New("terminal event was not found")
	}
	exchange.Events = filtered
	return nil
}

func duplicateTerminal(exchange *referenceserver.Exchange) error {
	if !exchange.Streaming {
		return errors.New("streaming scenario is required")
	}
	for index := len(exchange.Events) - 1; index >= 0; index-- {
		if exchange.Events[index].Terminal {
			exchange.Events = append(exchange.Events, exchange.Events[index])
			return nil
		}
	}
	return errors.New("terminal event was not found")
}

func changeToolCallID(exchange *referenceserver.Exchange) error {
	if !exchange.Streaming || exchange.Scenario != referenceserver.ScenarioTool {
		return errors.New("streaming tool scenario is required")
	}
	for index := len(exchange.Events) - 1; index >= 0; index-- {
		data, _ := exchange.Events[index].Data.(map[string]any)
		switch exchange.Protocol {
		case referenceserver.ProtocolOpenAIChat:
			choice := firstMap(data["choices"])
			delta := mapValue(choice, "delta")
			calls, _ := delta["tool_calls"].([]any)
			if len(calls) > 0 {
				calls[0].(map[string]any)["id"] = "call_mutated_0001"
				return nil
			}
		case referenceserver.ProtocolOpenAIResponses:
			if data["type"] == "response.output_item.done" {
				mapValue(data, "item")["call_id"] = "call_mutated_0001"
				return nil
			}
		case referenceserver.ProtocolAnthropic:
			if exchange.Events[index].Event == "content_block_stop" {
				data["id"] = "call_mutated_0001"
				return nil
			}
		}
	}
	return errors.New("tool call relationship was not found")
}

func injectUnknownEvent(exchange *referenceserver.Exchange) error {
	if !exchange.Streaming {
		return errors.New("streaming scenario is required")
	}
	event := referenceserver.SSEEvent{
		Event: "fixture.unknown",
		Data:  map[string]any{"type": "fixture.unknown", "payload": "must_be_ignored_by_tolerant_clients"},
	}
	terminal := firstTerminalIndex(exchange.Events)
	if terminal < 0 {
		return errors.New("terminal event was not found")
	}
	insertEvents(exchange, terminal, event)
	return nil
}

func unclosedReasoning(exchange *referenceserver.Exchange) error {
	if !exchange.Streaming {
		return errors.New("streaming scenario is required")
	}
	terminal := firstTerminalIndex(exchange.Events)
	if terminal < 0 {
		return errors.New("terminal event was not found")
	}
	var injected []referenceserver.SSEEvent
	switch exchange.Protocol {
	case referenceserver.ProtocolOpenAIResponses:
		injected = []referenceserver.SSEEvent{{
			Event: "response.output_item.added",
			Data: map[string]any{
				"type": "response.output_item.added", "output_index": 1,
				"item": map[string]any{"id": "item_reasoning_open", "type": "reasoning", "status": "in_progress"},
			},
		}}
	case referenceserver.ProtocolAnthropic:
		injected = []referenceserver.SSEEvent{
			{Event: "content_block_start", Data: map[string]any{"type": "content_block_start", "index": 1, "content_block": map[string]any{"type": "thinking", "thinking": ""}}},
			{Event: "content_block_delta", Data: map[string]any{"type": "content_block_delta", "index": 1, "delta": map[string]any{"type": "thinking_delta", "thinking": "unfinished"}}},
		}
	default:
		return errors.New("protocol has no reasoning block in this fixture")
	}
	insertEvents(exchange, terminal, injected...)
	return nil
}

func inconsistentUsage(exchange *referenceserver.Exchange) error {
	if !exchange.Streaming {
		usage := mapValue(exchange.JSON, "usage")
		if exchange.Protocol == referenceserver.ProtocolAnthropic {
			usage["output_tokens"] = 999
		} else {
			usage["total_tokens"] = 1
		}
		return nil
	}
	for index := len(exchange.Events) - 1; index >= 0; index-- {
		data, _ := exchange.Events[index].Data.(map[string]any)
		if usage, ok := data["usage"].(map[string]any); ok {
			if exchange.Protocol == referenceserver.ProtocolAnthropic {
				usage["output_tokens"] = 999
			} else {
				usage["total_tokens"] = 1
			}
			return nil
		}
		if response, ok := data["response"].(map[string]any); ok {
			if usage, ok := response["usage"].(map[string]any); ok {
				usage["total_tokens"] = 1
				return nil
			}
		}
	}
	return errors.New("usage was not found")
}

func truncatedUTF8(exchange *referenceserver.Exchange) error {
	if !exchange.Streaming {
		return errors.New("streaming scenario is required")
	}
	terminal := firstTerminalIndex(exchange.Events)
	if terminal < 0 {
		return errors.New("terminal event was not found")
	}
	broken := referenceserver.SSEEvent{Event: "fixture.truncated", RawData: []byte{'{', '"', 'x', '"', ':', '"', 0xe2, 0x82}}
	exchange.Events = slices.Insert(exchange.Events, terminal, broken)
	return nil
}

func firstTerminalIndex(events []referenceserver.SSEEvent) int {
	for index, event := range events {
		if event.Terminal {
			return index
		}
	}
	return -1
}

func insertEvents(exchange *referenceserver.Exchange, index int, inserted ...referenceserver.SSEEvent) {
	if exchange.Protocol == referenceserver.ProtocolOpenAIResponses && index < len(exchange.Events) {
		nextData, _ := exchange.Events[index].Data.(map[string]any)
		next, _ := nextData["sequence_number"].(int)
		if next > 0 {
			for offset := range inserted {
				data, _ := inserted[offset].Data.(map[string]any)
				if data != nil {
					data["sequence_number"] = next + offset
				}
			}
			for eventIndex := index; eventIndex < len(exchange.Events); eventIndex++ {
				data, _ := exchange.Events[eventIndex].Data.(map[string]any)
				if sequence, ok := data["sequence_number"].(int); ok {
					data["sequence_number"] = sequence + len(inserted)
				}
			}
		}
	}
	exchange.Events = slices.Insert(exchange.Events, index, inserted...)
}

func firstMap(value any) map[string]any {
	items, _ := value.([]any)
	if len(items) == 0 {
		return map[string]any{}
	}
	result, _ := items[0].(map[string]any)
	if result == nil {
		return map[string]any{}
	}
	return result
}

func mapValue(parent map[string]any, key string) map[string]any {
	if parent == nil {
		return map[string]any{}
	}
	value, _ := parent[key].(map[string]any)
	if value == nil {
		return map[string]any{}
	}
	return value
}

func cloneMap(source map[string]any) map[string]any {
	clone := make(map[string]any, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}
