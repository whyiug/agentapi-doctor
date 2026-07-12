package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"strings"

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
	fmt.Fprintf(&output, "Run: %s\nProfile outcome: %s\n", bundle.RunID, strings.ToUpper(string(bundle.Outcome)))
	fmt.Fprintf(&output, "Cases: %d candidate / %d applicable / %d executed\n", bundle.Denominators.CandidateCount, bundle.Denominators.ApplicableCount, bundle.Denominators.ExecutedCount)
	fmt.Fprintf(&output, "Verdicts: PASS %d | FAIL %d | WARN %d | INCONCLUSIVE %d | SKIPPED %d | ERRORED %d\n", counts.Pass, counts.Fail, counts.Warn, counts.Inconclusive, counts.Skipped, counts.Errored)
	for _, result := range sortedCases(bundle) {
		label := strings.ToUpper(string(result.ExecutionStatus))
		if result.Verdict != nil {
			label = strings.ToUpper(string(*result.Verdict))
		}
		reason := ""
		if result.ReasonCode != "" {
			reason = " (" + safeLine(string(result.ReasonCode)) + ")"
		}
		fmt.Fprintf(&output, "%-14s %s%s\n", label, safeLine(result.ScenarioID), reason)
	}
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
	log := sarifLog{Version: "2.1.0", Schema: "https://json.schemastore.org/sarif-2.1.0.json", Runs: []sarifRun{{Tool: sarifTool{Driver: sarifDriver{Name: "agentapi-doctor", InformationURI: "https://github.com/whyiug/agentapi-doctor", SemanticVersion: "0.1.0", Rules: ruleList}}, Results: results}}}
	return json.MarshalIndent(log, "", "  ")
}

func Markdown(bundle Bundle) ([]byte, error) {
	if err := bundle.Validate(); err != nil {
		return nil, err
	}
	counts := Count(bundle)
	var output strings.Builder
	fmt.Fprintf(&output, "# AgentAPI Doctor report\n\n- Run: `%s`\n- Profile: `%s@%s`\n- Outcome: **%s**\n- Exit code: `%d`\n\n", bundle.RunID, markdownInline(string(bundle.Profile.Name)), markdownInline(bundle.Profile.Version), strings.ToUpper(string(bundle.Outcome)), bundle.PrimaryExitCode)
	fmt.Fprintf(&output, "| Pass | Fail | Warn | Inconclusive | Skipped | Errored |\n|---:|---:|---:|---:|---:|---:|\n| %d | %d | %d | %d | %d | %d |\n\n", counts.Pass, counts.Fail, counts.Warn, counts.Inconclusive, counts.Skipped, counts.Errored)
	output.WriteString("| Scenario | Disposition | Execution | Verdict | Reason |\n|---|---|---|---|---|\n")
	for _, result := range sortedCases(bundle) {
		verdict := "—"
		if result.Verdict != nil {
			verdict = string(*result.Verdict)
		}
		fmt.Fprintf(&output, "| %s | %s | %s | %s | %s |\n", markdownCell(result.ScenarioID), result.PlanDisposition, result.ExecutionStatus, verdict, markdownCell(string(result.ReasonCode)))
	}
	return []byte(output.String()), nil
}

var htmlReportTemplate = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<title>AgentAPI Doctor report</title><style>body{font:15px system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#161616}table{border-collapse:collapse;width:100%}th,td{border:1px solid #bbb;padding:.45rem;text-align:left}code{overflow-wrap:anywhere}.pass{color:#086b2d}.fail{color:#a40000}.muted{color:#555}</style></head>
<body><h1>AgentAPI Doctor report</h1><p><strong>Run:</strong> <code>{{.RunID}}</code><br><strong>Profile:</strong> <code>{{.Profile.Name}}@{{.Profile.Version}}</code><br><strong>Outcome:</strong> {{.Outcome}}</p>
<p class="muted">Candidate {{.Denominators.CandidateCount}}, applicable {{.Denominators.ApplicableCount}}, executed {{.Denominators.ExecutedCount}}. This report is an observation, not vendor certification.</p>
<table><thead><tr><th>Scenario</th><th>Disposition</th><th>Execution</th><th>Verdict</th><th>Reason</th></tr></thead><tbody>{{range .Cases}}<tr><td>{{.ScenarioID}}</td><td>{{.PlanDisposition}}</td><td>{{.ExecutionStatus}}</td><td>{{if .Verdict}}{{.Verdict}}{{else}}—{{end}}</td><td>{{.ReasonCode}}</td></tr>{{end}}</tbody></table></body></html>`))

func HTML(bundle Bundle) ([]byte, error) {
	if err := bundle.Validate(); err != nil {
		return nil, err
	}
	copyBundle := bundle
	copyBundle.Cases = sortedCases(bundle)
	var output bytes.Buffer
	if err := htmlReportTemplate.Execute(&output, copyBundle); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func safeLine(value string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\x00' {
			return ' '
		}
		return r
	}, value)
}
func markdownInline(value string) string { return strings.ReplaceAll(safeLine(value), "`", "\\`") }
func markdownCell(value string) string   { return strings.ReplaceAll(markdownInline(value), "|", "\\|") }
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
