package oracle

import (
	"encoding/json"
	"fmt"

	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

// EvaluateRelations checks stable interaction, parent, and tool-call
// relationships. Lossy or unavailable normalization remains inconclusive.
func EvaluateRelations(input Input[[]schema.IRItem]) Outcome {
	if result := preflight(input); result != nil {
		return *result
	}
	if !input.Complete {
		return insufficient(input.EvidenceRefs, "incomplete_relational_evidence", "complete interaction", "partial IR")
	}
	if len(input.Value) == 0 {
		return insufficient(input.EvidenceRefs, "empty_interaction", "at least one normalized item", "none")
	}
	items := make(map[string]schema.IRItem, len(input.Value))
	calls := make(map[string]string)
	results := make(map[string]struct{})
	interactionID := ""
	for index, item := range input.Value {
		if err := item.Validate(); err != nil {
			return harness(input.EvidenceRefs, "invalid_normalized_ir", fmt.Errorf("item %d: %w", index, err))
		}
		if len(item.NormalizedValue) > 0 && !json.Valid(item.NormalizedValue) {
			return harness(input.EvidenceRefs, "invalid_normalized_ir", fmt.Errorf("item %d has invalid normalized JSON", index))
		}
		if len(item.LossMarkers) > 0 || len(item.Unavailable) > 0 {
			return insufficient(input.EvidenceRefs, "normalization_loss", "round-trippable relation fields", fmt.Sprintf("item %s has loss/unavailable markers", item.ItemID))
		}
		if interactionID == "" {
			interactionID = item.InteractionID
		} else if item.InteractionID != interactionID {
			return targetFail(input.EvidenceRefs, "cross_interaction_reference", interactionID, item.InteractionID)
		}
		if _, exists := items[item.ItemID]; exists {
			return targetFail(input.EvidenceRefs, "duplicate_item_id", "unique item ID", item.ItemID)
		}
		if item.ParentItemID != "" {
			if _, exists := items[item.ParentItemID]; !exists {
				return targetFail(input.EvidenceRefs, "unknown_parent_item", "previous item ID", item.ParentItemID)
			}
		}
		switch item.IRType {
		case schema.IRToolCall:
			if item.CallID == "" {
				return targetFail(input.EvidenceRefs, "missing_call_id", "nonempty tool call ID", "empty")
			}
			if prior, exists := calls[item.CallID]; exists {
				return targetFail(input.EvidenceRefs, "duplicate_call_id", "unique call ID", fmt.Sprintf("%s already used by %s", item.CallID, prior))
			}
			calls[item.CallID] = item.ItemID
		case schema.IRToolResult:
			if item.CallID == "" {
				return targetFail(input.EvidenceRefs, "missing_tool_result_call_id", "known call ID", "empty")
			}
			if _, exists := calls[item.CallID]; !exists {
				return targetFail(input.EvidenceRefs, "tool_result_unknown_call", "previous tool call ID", item.CallID)
			}
			if _, exists := results[item.CallID]; exists {
				return targetFail(input.EvidenceRefs, "duplicate_tool_result", "one result per call ID", item.CallID)
			}
			results[item.CallID] = struct{}{}
		}
		items[item.ItemID] = item
	}
	return pass(input.EvidenceRefs)
}
