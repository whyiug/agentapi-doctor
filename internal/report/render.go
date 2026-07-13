package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"strings"
	"unicode"

	"github.com/whyiug/agentapi-doctor/internal/buildinfo"
	"github.com/whyiug/agentapi-doctor/pkg/schema"
)

func JSON(bundle Bundle) ([]byte, error) {
	if err := bundle.Validate(); err != nil {
		return nil, err
	}
	return schema.CanonicalMarshal(bundle)
}

func Terminal(bundle Bundle) ([]byte, error) {
	if err := bundle.Validate(); err != nil {
		return nil, err
	}
	counts := Count(bundle)
	var output strings.Builder
	fmt.Fprintf(&output, "Run: %s\nResult: %s\n", bundle.RunID, strings.ToUpper(humanCheckResult(bundle.Outcome)))
	fmt.Fprintf(&output, "Cases: %d candidate / %d applicable / %d executed\n", bundle.Denominators.CandidateCount, bundle.Denominators.ApplicableCount, bundle.Denominators.ExecutedCount)
	fmt.Fprintf(&output, "Verdicts: PASS %d | FAIL %d | WARN %d | INCONCLUSIVE %d | SKIPPED %d | ERRORED %d\n", counts.Pass, counts.Fail, counts.Warn, counts.Inconclusive, counts.Skipped, counts.Errored)
	if len(bundle.Conditions) > 0 {
		output.WriteString("\nImportant conditions:\n")
		for _, condition := range bundle.Conditions {
			fmt.Fprintf(&output, "  [%s] %s\n", safeLine(condition.Code), safeLine(condition.Message))
		}
		output.WriteByte('\n')
	}
	for _, result := range sortedCases(bundle) {
		item := presentCase(result)
		if !item.Detailed {
			fmt.Fprintf(&output, "%-14s %s%s\n", item.Label, item.ScenarioID, parenthesizedReason(item.Reason))
			continue
		}
		fmt.Fprintf(&output, "%-14s %s [%s]\n", item.Label, item.ScenarioName, item.ScenarioID)
		if item.Reason != "" {
			fmt.Fprintf(&output, "  Reason: %s\n", item.Reason)
		}
		if len(item.Findings) == 0 {
			fmt.Fprintf(&output, "  Finding category: %s\n  Fault domain: %s\n", item.Category, item.FaultDomain)
			fmt.Fprintf(&output, "  Next action: %s\n", item.NextAction)
		}
		for index, finding := range item.Findings {
			prefix := "Finding"
			if len(item.Findings) > 1 {
				prefix = fmt.Sprintf("Finding %d", index+1)
			}
			fmt.Fprintf(&output, "  %s category: %s\n  %s fault domain: %s\n", prefix, finding.Category, prefix, finding.FaultDomain)
			if finding.Remediation != "" {
				fmt.Fprintf(&output, "  Remediation: %s\n", finding.Remediation)
			}
		}
		for _, assertion := range item.Assertions {
			fmt.Fprintf(&output, "  Assertion %s\n    Expected: %s\n    Observed: %s\n", assertion.ID, assertion.Expected, assertion.Observed)
		}
	}
	fmt.Fprintf(&output, "\nNext: export a shareable report with:\n  doctor report markdown %s --output doctor-report.md\n", bundle.RunID)
	return []byte(output.String()), nil
}

type junitSuites struct {
	XMLName  xml.Name     `xml:"testsuites"`
	Name     string       `xml:"name,attr"`
	Tests    int          `xml:"tests,attr"`
	Failures int          `xml:"failures,attr"`
	Errors   int          `xml:"errors,attr"`
	Skipped  int          `xml:"skipped,attr"`
	Suites   []junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Errors   int         `xml:"errors,attr"`
	Skipped  int         `xml:"skipped,attr"`
	Cases    []junitCase `xml:"testcase"`
}

type junitCase struct {
	Name      string        `xml:"name,attr"`
	Classname string        `xml:"classname,attr"`
	Failure   *junitMessage `xml:"failure,omitempty"`
	Error     *junitMessage `xml:"error,omitempty"`
	Skipped   *junitMessage `xml:"skipped,omitempty"`
}

type junitMessage struct {
	Message string `xml:"message,attr"`
	Text    string `xml:",chardata"`
}

func JUnit(bundle Bundle) ([]byte, error) {
	if err := bundle.Validate(); err != nil {
		return nil, err
	}
	suite := junitSuite{Name: string(bundle.Profile.Name), Tests: len(bundle.Cases)}
	for _, result := range sortedCases(bundle) {
		item := junitCase{Name: result.ScenarioID, Classname: string(bundle.Profile.Name)}
		switch {
		case result.ExecutionStatus == schema.ExecutionErrored || result.ExecutionStatus == schema.ExecutionCancelled:
			item.Error = &junitMessage{Message: string(result.ReasonCode), Text: "harness or driver did not produce a target verdict"}
			suite.Errors++
		case result.PlanDisposition != schema.DispositionExecute || result.ExecutionStatus == schema.ExecutionSkipped:
			item.Skipped = &junitMessage{Message: string(result.ReasonCode)}
			suite.Skipped++
		case result.Verdict != nil && *result.Verdict == schema.VerdictFail:
			item.Failure = &junitMessage{Message: "target assertion failed", Text: findingText(result)}
			suite.Failures++
		case result.Verdict != nil && (*result.Verdict == schema.VerdictInconclusive || *result.Verdict == schema.VerdictWarn):
			item.Skipped = &junitMessage{Message: string(*result.Verdict), Text: "no conformance failure was asserted"}
			suite.Skipped++
		}
		suite.Cases = append(suite.Cases, item)
	}
	root := junitSuites{Name: "agentapi-doctor", Tests: suite.Tests, Failures: suite.Failures, Errors: suite.Errors, Skipped: suite.Skipped, Suites: []junitSuite{suite}}
	encoded, err := xml.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), encoded...), nil
}

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name            string      `json:"name"`
	InformationURI  string      `json:"informationUri"`
	SemanticVersion string      `json:"semanticVersion"`
	Rules           []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	ShortDescription sarifText `json:"shortDescription"`
}
type sarifText struct {
	Text string `json:"text"`
}
type sarifResult struct {
	RuleID     string         `json:"ruleId"`
	Level      string         `json:"level"`
	Message    sarifText      `json:"message"`
	Properties map[string]any `json:"properties"`
}

func SARIF(bundle Bundle) ([]byte, error) {
	if err := bundle.Validate(); err != nil {
		return nil, err
	}
	rules := map[string]sarifRule{}
	results := []sarifResult{}
	for _, result := range sortedCases(bundle) {
		for _, finding := range result.Findings {
			ruleID := finding.RequirementID
			if ruleID == "" {
				ruleID = finding.Category
			}
			if ruleID == "" {
				ruleID = "agentapi-doctor.finding"
			}
			rules[ruleID] = sarifRule{ID: ruleID, Name: finding.Category, ShortDescription: sarifText{Text: "Agent API compatibility finding"}}
			results = append(results, sarifResult{RuleID: ruleID, Level: sarifLevel(finding.Severity), Message: sarifText{Text: safeLine(finding.RemediationHint)}, Properties: map[string]any{
				"scenario_id": result.ScenarioID, "fault_domain": finding.FaultDomain, "fault_family": finding.FaultFamily,
				"confidence": finding.Confidence, "fingerprint": finding.Fingerprint, "not_source_code_vulnerability": true,
			}})
		}
	}
	ruleList := make([]sarifRule, 0, len(rules))
	for _, rule := range rules {
		ruleList = append(ruleList, rule)
	}
	for i := 0; i < len(ruleList); i++ {
		for j := i + 1; j < len(ruleList); j++ {
			if ruleList[j].ID < ruleList[i].ID {
				ruleList[i], ruleList[j] = ruleList[j], ruleList[i]
			}
		}
	}
	log := sarifLog{Version: "2.1.0", Schema: "https://json.schemastore.org/sarif-2.1.0.json", Runs: []sarifRun{{Tool: sarifTool{Driver: sarifDriver{Name: "agentapi-doctor", InformationURI: "https://github.com/whyiug/agentapi-doctor", SemanticVersion: buildinfo.Current().Version, Rules: ruleList}}, Results: results}}}
	return json.MarshalIndent(log, "", "  ")
}

func Markdown(bundle Bundle) ([]byte, error) {
	if err := bundle.Validate(); err != nil {
		return nil, err
	}
	counts := Count(bundle)
	var output strings.Builder
	fmt.Fprintf(&output, "# AgentAPI Doctor report\n\n- Run: `%s`\n- Profile: `%s@%s`\n- Result: **%s**\n- Exit code: `%d`\n\n", bundle.RunID, markdownInline(string(bundle.Profile.Name)), markdownInline(bundle.Profile.Version), humanCheckResult(bundle.Outcome), bundle.PrimaryExitCode)
	if len(bundle.Conditions) > 0 {
		output.WriteString("## Important conditions\n\n")
		for _, condition := range bundle.Conditions {
			fmt.Fprintf(&output, "- **%s**: %s\n", markdownInline(condition.Code), markdownInline(condition.Message))
		}
		output.WriteByte('\n')
	}
	fmt.Fprintf(&output, "| Pass | Fail | Warn | Inconclusive | Skipped | Errored |\n|---:|---:|---:|---:|---:|---:|\n| %d | %d | %d | %d | %d | %d |\n\n", counts.Pass, counts.Fail, counts.Warn, counts.Inconclusive, counts.Skipped, counts.Errored)
	output.WriteString("| Scenario | Disposition | Execution | Verdict | Reason |\n|---|---|---|---|---|\n")
	for _, result := range sortedCases(bundle) {
		item := presentCase(result)
		scenario := item.ScenarioID
		if item.Detailed {
			scenario = item.ScenarioName + " (" + item.ScenarioID + ")"
		}
		fmt.Fprintf(&output, "| %s | %s | %s | %s | %s |\n", markdownCell(scenario), result.PlanDisposition, result.ExecutionStatus, markdownCell(item.Label), markdownCell(item.Reason))
	}
	for _, result := range sortedCases(bundle) {
		item := presentCase(result)
		if !item.Detailed {
			continue
		}
		fmt.Fprintf(&output, "\n## %s — %s\n\n", markdownInline(item.Label), markdownInline(item.ScenarioName))
		fmt.Fprintf(&output, "- Scenario ID: `%s`\n- Finding category: %s\n- Fault domain: %s\n", markdownInline(item.ScenarioID), markdownInline(item.Category), markdownInline(item.FaultDomain))
		if item.Reason != "" {
			fmt.Fprintf(&output, "- Reason: %s\n", markdownInline(item.Reason))
		}
		for _, assertion := range item.Assertions {
			fmt.Fprintf(&output, "- Assertion `%s`\n  - Expected: %s\n  - Observed: %s\n", markdownInline(assertion.ID), markdownInline(assertion.Expected), markdownInline(assertion.Observed))
		}
		for index, finding := range item.Findings {
			if len(item.Findings) > 1 {
				fmt.Fprintf(&output, "- Finding %d: category %s; fault domain %s\n", index+1, markdownInline(finding.Category), markdownInline(finding.FaultDomain))
			}
			if finding.Remediation != "" {
				fmt.Fprintf(&output, "- Remediation: %s\n", markdownInline(finding.Remediation))
			}
		}
		if item.NextAction != "" && len(item.Findings) == 0 {
			fmt.Fprintf(&output, "- Next action: %s\n", markdownInline(item.NextAction))
		}
	}
	return []byte(output.String()), nil
}

var htmlReportTemplate = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<title>AgentAPI Doctor report</title><style>body{font:15px system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#161616}table{border-collapse:collapse;width:100%}th,td{border:1px solid #bbb;padding:.45rem;text-align:left;vertical-align:top}code{overflow-wrap:anywhere}.pass{color:#086b2d}.fail{color:#a40000}.muted{color:#555}.conditions{border:2px solid #8a5a00;background:#fff8e6;margin:1rem 0;padding:.25rem 1rem}.conditions h2{font-size:1.1rem}.diagnostic{border-left:4px solid #a40000;background:#f7f7f7;margin:1rem 0;padding:.25rem 1rem}.diagnostic h2{font-size:1.1rem}.diagnostic dt{font-weight:700;margin-top:.5rem}.diagnostic dd{margin-left:0}</style></head>
<body><h1>AgentAPI Doctor report</h1><p><strong>Run:</strong> <code>{{.RunID}}</code><br><strong>Profile:</strong> <code>{{.Profile.Name}}@{{.Profile.Version}}</code><br><strong>Result:</strong> {{.CheckResult}}</p>
<p class="muted">Candidate {{.Denominators.CandidateCount}}, applicable {{.Denominators.ApplicableCount}}, executed {{.Denominators.ExecutedCount}}. This report is an observation, not vendor certification.</p>
{{if .PresentedConditions}}<section class="conditions"><h2>Important conditions</h2><ul>{{range .PresentedConditions}}<li><strong><code>{{.Code}}</code></strong>: {{.Message}}</li>{{end}}</ul></section>{{end}}
<table><thead><tr><th>Scenario</th><th>Disposition</th><th>Execution</th><th>Verdict</th><th>Reason</th></tr></thead><tbody>{{range .Cases}}<tr><td>{{if .Detailed}}<strong>{{.ScenarioName}}</strong><br>{{end}}<code>{{.ScenarioID}}</code></td><td>{{.PlanDisposition}}</td><td>{{.ExecutionStatus}}</td><td>{{.Label}}</td><td>{{.Reason}}</td></tr>{{end}}</tbody></table>
{{range .Cases}}{{if .Detailed}}<section class="diagnostic"><h2>{{.Label}} — {{.ScenarioName}}</h2><dl><dt>Scenario ID</dt><dd><code>{{.ScenarioID}}</code></dd>{{if not .Findings}}<dt>Finding category</dt><dd>{{.Category}}</dd><dt>Fault domain</dt><dd>{{.FaultDomain}}</dd>{{end}}{{if .Reason}}<dt>Reason</dt><dd>{{.Reason}}</dd>{{end}}{{if .NextAction}}<dt>Next action</dt><dd>{{.NextAction}}</dd>{{end}}</dl>
{{range .Assertions}}<p><strong>Assertion <code>{{.ID}}</code></strong><br><strong>Expected:</strong> {{.Expected}}<br><strong>Observed:</strong> {{.Observed}}</p>{{end}}
{{range .Findings}}<p><strong>Finding category:</strong> {{.Category}}<br><strong>Fault domain:</strong> {{.FaultDomain}}{{if .Remediation}}<br><strong>Remediation:</strong> {{.Remediation}}{{end}}</p>{{end}}</section>{{end}}{{end}}</body></html>`))

func HTML(bundle Bundle) ([]byte, error) {
	if err := bundle.Validate(); err != nil {
		return nil, err
	}
	view := htmlReportView{Bundle: bundle, CheckResult: humanCheckResult(bundle.Outcome)}
	for _, condition := range bundle.Conditions {
		view.PresentedConditions = append(view.PresentedConditions, Condition{Code: safeLine(condition.Code), Message: safeLine(condition.Message)})
	}
	for _, result := range sortedCases(bundle) {
		view.Cases = append(view.Cases, presentCase(result))
	}
	var output bytes.Buffer
	if err := htmlReportTemplate.Execute(&output, view); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func safeLine(value string) string {
	runes := []rune(value)
	var output strings.Builder
	for index := 0; index < len(runes); index++ {
		r := runes[index]
		if r == '\x1b' {
			index = skipEscapeSequence(runes, index)
			continue
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			output.WriteRune(' ')
			continue
		}
		output.WriteRune(r)
	}
	return output.String()
}

func skipEscapeSequence(runes []rune, escape int) int {
	if escape+1 >= len(runes) {
		return escape
	}
	switch runes[escape+1] {
	case '[': // Control Sequence Introducer: ESC [ ... final-byte.
		for index := escape + 2; index < len(runes); index++ {
			if runes[index] >= 0x40 && runes[index] <= 0x7e {
				return index
			}
		}
		return len(runes) - 1
	case ']': // Operating System Command: ESC ] ... BEL or ST.
		for index := escape + 2; index < len(runes); index++ {
			if runes[index] == '\a' {
				return index
			}
			if runes[index] == '\x1b' && index+1 < len(runes) && runes[index+1] == '\\' {
				return index + 1
			}
		}
		return len(runes) - 1
	default:
		return escape + 1
	}
}
func markdownInline(value string) string {
	return strings.NewReplacer(
		"\\", "\\\\", "`", "\\`", "*", "\\*", "_", "\\_", "[", "\\[", "]", "\\]",
		"<", "&lt;", ">", "&gt;", "&", "&amp;",
	).Replace(safeLine(value))
}
func markdownCell(value string) string { return strings.ReplaceAll(markdownInline(value), "|", "\\|") }

type htmlReportView struct {
	Bundle
	CheckResult         string
	PresentedConditions []Condition
	Cases               []casePresentation
}

func humanCheckResult(outcome schema.ProfileOutcome) string {
	switch outcome {
	case schema.ProfileCompatible:
		return "checks passed"
	case schema.ProfileDegraded:
		return "checks passed with warnings"
	case schema.ProfileIncompatible:
		return "checks failed"
	case schema.ProfileInconclusive:
		return "checks inconclusive"
	default:
		return "checks inconclusive"
	}
}

type casePresentation struct {
	ScenarioID      string
	ScenarioName    string
	PlanDisposition schema.PlanDisposition
	ExecutionStatus schema.ExecutionStatus
	Label           string
	Reason          string
	Detailed        bool
	Category        string
	FaultDomain     string
	NextAction      string
	Assertions      []assertionPresentation
	Findings        []findingPresentation
}

type assertionPresentation struct {
	ID       string
	Expected string
	Observed string
}

type findingPresentation struct {
	Category    string
	FaultDomain string
	Remediation string
}

func presentCase(result schema.CaseResult) casePresentation {
	label := strings.ToUpper(string(result.ExecutionStatus))
	if result.Verdict != nil {
		label = strings.ToUpper(string(*result.Verdict))
	}
	item := casePresentation{
		ScenarioID: safeLine(result.ScenarioID), ScenarioName: humanScenarioName(result.ScenarioID),
		PlanDisposition: result.PlanDisposition, ExecutionStatus: result.ExecutionStatus,
		Label: safeLine(label), Reason: safeLine(string(result.ReasonCode)),
		Category: "not recorded", FaultDomain: "not attributed",
	}
	if result.Verdict != nil {
		item.Detailed = *result.Verdict == schema.VerdictFail || *result.Verdict == schema.VerdictWarn || *result.Verdict == schema.VerdictInconclusive
	}
	if item.Reason != "" {
		item.Category = item.Reason
	}
	for _, finding := range result.Findings {
		entry := findingPresentation{
			Category:    safeFallback(finding.Category, "not recorded"),
			FaultDomain: safeFallback(finding.FaultDomain, "not attributed"),
			Remediation: safeLine(finding.RemediationHint),
		}
		item.Findings = append(item.Findings, entry)
		if len(item.Findings) == 1 {
			item.Category, item.FaultDomain = entry.Category, entry.FaultDomain
		}
	}
	if item.Detailed && len(item.Findings) == 0 {
		item.NextAction = "Review the expected and observed prerequisite with the saved evidence; no fault domain was attributed."
	}
	for _, assertion := range result.AssertionResults {
		if assertion.Verdict == schema.VerdictPass {
			continue
		}
		item.Assertions = append(item.Assertions, assertionPresentation{
			ID:       safeFallback(assertion.AssertionID, "unnamed"),
			Expected: displayValue(assertion.Expected), Observed: displayValue(assertion.Observed),
		})
	}
	return item
}

func parenthesizedReason(reason string) string {
	if reason == "" {
		return ""
	}
	return " (" + reason + ")"
}

func safeFallback(value, fallback string) string {
	value = strings.TrimSpace(safeLine(value))
	if value == "" {
		return fallback
	}
	return value
}

func displayValue(value any) string {
	if value == nil {
		return "not recorded"
	}
	if text, ok := value.(string); ok {
		if text == "" {
			return `""`
		}
		return safeLine(text)
	}
	encoded, err := schema.CanonicalMarshal(value)
	if err != nil {
		return safeLine(fmt.Sprint(value))
	}
	return safeLine(string(encoded))
}

func humanScenarioName(identifier string) string {
	parts := strings.FieldsFunc(safeLine(identifier), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	for index, part := range parts {
		if allDigits(part) && index+1 < len(parts) {
			parts = parts[index+1:]
			break
		}
	}
	words := make([]string, 0, len(parts))
	for _, part := range parts {
		if allDigits(part) {
			continue
		}
		switch strings.ToLower(part) {
		case "openai":
			words = append(words, "OpenAI")
		case "api":
			words = append(words, "API")
		case "http":
			words = append(words, "HTTP")
		case "https":
			words = append(words, "HTTPS")
		case "sse":
			words = append(words, "SSE")
		case "id":
			words = append(words, "ID")
		case "json":
			words = append(words, "JSON")
		default:
			runes := []rune(strings.ToLower(part))
			if len(runes) > 0 {
				runes[0] = unicode.ToUpper(runes[0])
			}
			words = append(words, string(runes))
		}
	}
	if len(words) == 0 {
		return "Unnamed scenario"
	}
	return strings.Join(words, " ")
}

func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}
func findingText(result schema.CaseResult) string {
	if len(result.Findings) == 0 {
		return "failure recorded without a derived finding"
	}
	return safeLine(result.Findings[0].RemediationHint)
}
func sarifLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "error", "critical", "high", "must":
		return "error"
	case "warning", "medium", "should":
		return "warning"
	default:
		return "note"
	}
}
