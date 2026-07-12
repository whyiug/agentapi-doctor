package packapi

import (
	"errors"
	"fmt"
	"strings"
)

const MaxExpandedTemplateBytes = 1 << 20

// ExpandTemplateString performs literal substitution from an explicit value
// map. It does not evaluate expressions, recurse into replacement values, read
// environment variables, or access files/network. Compilation must already
// have admitted each variable through CompileOptions.AllowedVariables.
func ExpandTemplateString(template string, values map[string]string) (string, error) {
	matches := templatePattern.FindAllStringSubmatchIndex(template, -1)
	remainder := templatePattern.ReplaceAllString(template, "")
	if strings.Contains(remainder, "{{") || strings.Contains(remainder, "}}") {
		return "", errors.New("malformed template expression")
	}
	var expanded strings.Builder
	last := 0
	for _, match := range matches {
		variable := template[match[2]:match[3]]
		value, exists := values[variable]
		if !exists {
			return "", fmt.Errorf("template variable %q has no resolved value", variable)
		}
		expanded.WriteString(template[last:match[0]])
		expanded.WriteString(value)
		if expanded.Len() > MaxExpandedTemplateBytes {
			return "", fmt.Errorf("expanded template exceeds %d bytes", MaxExpandedTemplateBytes)
		}
		last = match[1]
	}
	expanded.WriteString(template[last:])
	if expanded.Len() > MaxExpandedTemplateBytes {
		return "", fmt.Errorf("expanded template exceeds %d bytes", MaxExpandedTemplateBytes)
	}
	return expanded.String(), nil
}
