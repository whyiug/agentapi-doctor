package process_e2e_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	cliResultSchema    = "urn:agentapi-doctor:cli-result:v1alpha1"
	candidateCondition = "candidate_interpretations_pending_review"
)

type cliCondition struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type cliEnvelope struct {
	SchemaVersion   string          `json:"schema_version"`
	Status          string          `json:"status"`
	PrimaryExitCode int             `json:"primary_exit_code"`
	Conditions      []cliCondition  `json:"conditions"`
	Data            json.RawMessage `json:"data"`
}

type testSummary struct {
	RunID           string         `json:"run_id"`
	ProfileOutcome  string         `json:"profile_outcome"`
	PrimaryExitCode int            `json:"primary_exit_code"`
	RunStore        string         `json:"run_store"`
	Conditions      []cliCondition `json:"conditions"`
}

type inspectSummary struct {
	RunID        string `json:"run_id"`
	BundleDigest string `json:"bundle_digest"`
	Bundle       struct {
		RunID           string         `json:"run_id"`
		Outcome         string         `json:"profile_outcome"`
		PrimaryExitCode int            `json:"primary_exit_code"`
		Conditions      []cliCondition `json:"conditions"`
	} `json:"bundle"`
}

func TestQuickstartRunsThroughRealProcesses(t *testing.T) {
	repositoryRoot := sourceRepositoryRoot(t)
	buildRoot := t.TempDir()
	runtimeRoot := t.TempDir()
	buildEnvironment := isolatedEnvironment(t, filepath.Join(buildRoot, "environment"), true)
	runtimeEnvironment := isolatedEnvironment(t, filepath.Join(runtimeRoot, "environment"), false)
	assertNoAmbientCredentials(t, buildEnvironment)
	assertNoAmbientCredentials(t, runtimeEnvironment)

	doctor := buildBinary(t, repositoryRoot, buildRoot, buildEnvironment, "doctor", "./cmd/doctor")
	reference := buildBinary(t, repositoryRoot, buildRoot, buildEnvironment, "reference-server", "./cmd/reference-server")

	address, stopReference := startReferenceServer(t, reference, runtimeRoot, runtimeEnvironment)
	defer stopReference()
	host, portText, err := net.SplitHostPort(address)
	if err != nil || host != "127.0.0.1" {
		t.Fatalf("reference server did not select an IPv4 loopback address: %q (%v)", address, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1024 {
		t.Fatalf("reference server did not select a random high port: %q (%v)", portText, err)
	}
	waitForReferenceServer(t, address)

	workspace := filepath.Join(runtimeRoot, "workspace")
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatal(err)
	}

	initialized := runEnvelope(t, doctor, workspace, runtimeEnvironment, "init")
	assertPassingEnvelope(t, "init", initialized)
	var initData struct {
		Config string `json:"config"`
	}
	decodeData(t, "init", initialized.Data, &initData)
	wantConfig := filepath.Join(workspace, ".agentapi", "config.yaml")
	if !sameExistingPath(initData.Config, wantConfig) {
		t.Fatalf("init returned unexpected config path: %q", initData.Config)
	}

	baseURL := "http://" + address + "/v1"
	added := runEnvelope(t, doctor, workspace, runtimeEnvironment,
		"target", "add", "smoke",
		"--base-url", baseURL,
		"--protocol", "openai-responses",
		"--model", "fixture-model",
	)
	assertPassingEnvelope(t, "target add", added)
	var addData struct {
		Target string `json:"target"`
	}
	decodeData(t, "target add", added.Data, &addData)
	if addData.Target != "smoke" {
		t.Fatalf("target add returned unexpected target: %q", addData.Target)
	}

	tested := runEnvelope(t, doctor, workspace, runtimeEnvironment, "test", "smoke")
	assertPassingEnvelope(t, "test", tested)
	var summary testSummary
	decodeData(t, "test", tested.Data, &summary)
	if summary.RunID == "" || summary.PrimaryExitCode != 0 {
		t.Fatalf("test did not return a successful run identity: %#v", summary)
	}
	if summary.ProfileOutcome != "compatible" {
		t.Fatalf("test profile outcome = %q, want compatible", summary.ProfileOutcome)
	}
	if !hasCondition(summary.Conditions, candidateCondition) {
		t.Fatalf("test omitted the required candidate interpretation condition: %#v", summary.Conditions)
	}
	wantRunStore := filepath.Join(workspace, ".agentapi", "runs")
	if !sameExistingPath(summary.RunStore, wantRunStore) {
		t.Fatalf("test run store = %q, want %q", summary.RunStore, wantRunStore)
	}
	assertRegularFile(t, filepath.Join(wantRunStore, "latest.json"))
	assertRegularFile(t, filepath.Join(wantRunStore, summary.RunID, "record.json"))

	inspected := runEnvelope(t, doctor, workspace, runtimeEnvironment, "run", "inspect", "latest")
	assertPassingEnvelope(t, "run inspect", inspected)
	var persisted inspectSummary
	decodeData(t, "run inspect", inspected.Data, &persisted)
	if persisted.RunID != summary.RunID || persisted.Bundle.RunID != summary.RunID || persisted.BundleDigest == "" {
		t.Fatalf("run inspect did not load the persisted test run: %#v", persisted)
	}
	if persisted.Bundle.Outcome != "compatible" || persisted.Bundle.PrimaryExitCode != 0 {
		t.Fatalf("persisted report outcome is not compatible: %#v", persisted.Bundle)
	}
	if !hasCondition(persisted.Bundle.Conditions, candidateCondition) {
		t.Fatalf("persisted report omitted the candidate condition: %#v", persisted.Bundle.Conditions)
	}

	terminal := runPlain(t, doctor, workspace, runtimeEnvironment, "report", "terminal", "latest")
	for _, expected := range []string{
		"Run: " + summary.RunID,
		"Profile outcome: COMPATIBLE",
		"Cases: 4 candidate / 4 applicable / 4 executed",
		"Verdicts: PASS 4",
	} {
		if !strings.Contains(terminal, expected) {
			t.Fatalf("terminal report omitted %q:\n%s", expected, terminal)
		}
	}
}

func sourceRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate process e2e source file")
	}
	root, err := filepath.Abs(filepath.Join(filepath.Dir(source), "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(filepath.Join(root, "go.mod")); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("cannot locate repository go.mod from %q: %v", source, err)
	}
	return root
}

func buildBinary(t *testing.T, repositoryRoot, outputRoot string, environment []string, name, packagePath string) string {
	t.Helper()
	executable := name
	if runtime.GOOS == "windows" {
		executable += ".exe"
	}
	output := filepath.Join(outputRoot, executable)
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("locate Go tool: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, goTool, "build", "-trimpath", "-o", output, packagePath)
	command.Dir = repositoryRoot
	command.Env = environment
	combined, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("build %s: %v\n%s", name, err, combined)
	}
	return output
}

func isolatedEnvironment(t *testing.T, root string, build bool) []string {
	t.Helper()
	home := filepath.Join(root, "home")
	temporary := filepath.Join(root, "tmp")
	cache := filepath.Join(root, "cache")
	modules := filepath.Join(root, "modules")
	for _, directory := range []string{home, temporary, cache, modules} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	environment := []string{
		"HOME=" + home,
		"USERPROFILE=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(home, ".config"),
		"XDG_CACHE_HOME=" + cache,
		"TMPDIR=" + temporary,
		"TMP=" + temporary,
		"TEMP=" + temporary,
		"NO_PROXY=127.0.0.1,localhost",
		"no_proxy=127.0.0.1,localhost",
	}
	if build {
		environment = append(environment,
			"CGO_ENABLED=0",
			"GOCACHE="+filepath.Join(cache, "go-build"),
			"GOMODCACHE="+modules,
			"GOENV=off",
			"GOFLAGS=-mod=vendor",
			"GOTOOLCHAIN=local",
		)
	}
	if runtime.GOOS == "windows" {
		for _, key := range []string{"SYSTEMROOT", "WINDIR"} {
			if value, ok := os.LookupEnv(key); ok {
				environment = append(environment, key+"="+value)
			}
		}
	}
	return environment
}

func assertNoAmbientCredentials(t *testing.T, environment []string) {
	t.Helper()
	forbidden := map[string]struct{}{
		"ANTHROPIC_API_KEY":     {},
		"ANTHROPIC_AUTH_TOKEN":  {},
		"ARK_API_KEY":           {},
		"AWS_ACCESS_KEY_ID":     {},
		"AWS_SECRET_ACCESS_KEY": {},
		"GITHUB_TOKEN":          {},
		"GH_TOKEN":              {},
		"OPENAI_API_KEY":        {},
	}
	for _, entry := range environment {
		key, _, _ := strings.Cut(entry, "=")
		if _, found := forbidden[strings.ToUpper(key)]; found {
			t.Fatalf("isolated child environment contains ambient credential key %s", key)
		}
	}
}

type synchronizedLog struct {
	mu    sync.Mutex
	lines []string
}

func (log *synchronizedLog) append(line string) {
	log.mu.Lock()
	defer log.mu.Unlock()
	log.lines = append(log.lines, line)
}

func (log *synchronizedLog) String() string {
	log.mu.Lock()
	defer log.mu.Unlock()
	return strings.Join(log.lines, "\n")
}

func startReferenceServer(t *testing.T, executable, directory string, environment []string) (string, func()) {
	t.Helper()
	command := exec.Command(executable, "-listen", "127.0.0.1:0")
	command.Dir = directory
	command.Env = environment
	command.Stdout = io.Discard
	stderr, err := command.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start reference server: %v", err)
	}

	logs := &synchronizedLog{}
	addressReady := make(chan string, 1)
	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			logs.append(line)
			const marker = "listening on "
			if index := strings.LastIndex(line, marker); index >= 0 {
				address := strings.TrimSpace(line[index+len(marker):])
				select {
				case addressReady <- address:
				default:
				}
			}
		}
	}()

	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			if err := command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				t.Errorf("kill owned reference server: %v", err)
			}
			_ = command.Wait()
			select {
			case <-scanDone:
			case <-time.After(5 * time.Second):
				t.Errorf("reference server log reader did not stop")
			}
		})
	}

	select {
	case address := <-addressReady:
		return address, cleanup
	case <-time.After(10 * time.Second):
		cleanup()
		t.Fatalf("reference server did not report its loopback listener:\n%s", logs.String())
		return "", func() {}
	}
}

func waitForReferenceServer(t *testing.T, address string) {
	t.Helper()
	transport := &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
		DialContext: (&net.Dialer{
			Timeout: 250 * time.Millisecond,
		}).DialContext,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   500 * time.Millisecond,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("unexpected redirect from local reference server")
		},
	}
	deadline := time.Now().Add(10 * time.Second)
	url := "http://" + address + "/ready"
	var lastError error
	for time.Now().Before(deadline) {
		response, err := client.Get(url)
		if err == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			return
		}
		lastError = err
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("reference server was not ready at %s: %v", address, lastError)
}

func runEnvelope(t *testing.T, executable, directory string, environment []string, arguments ...string) cliEnvelope {
	t.Helper()
	stdout, stderr, err := runCommand(executable, directory, environment, arguments...)
	if err != nil {
		t.Fatalf("doctor %s: %v\nstdout:\n%s\nstderr:\n%s", strings.Join(arguments, " "), err, stdout, stderr)
	}
	if len(bytes.TrimSpace(stderr)) != 0 {
		t.Fatalf("doctor %s wrote unexpected stderr:\n%s", strings.Join(arguments, " "), stderr)
	}
	decoder := json.NewDecoder(bytes.NewReader(stdout))
	decoder.DisallowUnknownFields()
	var envelope cliEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		t.Fatalf("decode doctor %s envelope: %v\n%s", strings.Join(arguments, " "), err, stdout)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Fatalf("doctor %s emitted multiple JSON values: %v", strings.Join(arguments, " "), err)
	}
	return envelope
}

func runPlain(t *testing.T, executable, directory string, environment []string, arguments ...string) string {
	t.Helper()
	stdout, stderr, err := runCommand(executable, directory, environment, arguments...)
	if err != nil {
		t.Fatalf("doctor %s: %v\nstdout:\n%s\nstderr:\n%s", strings.Join(arguments, " "), err, stdout, stderr)
	}
	if len(bytes.TrimSpace(stderr)) != 0 {
		t.Fatalf("doctor %s wrote unexpected stderr:\n%s", strings.Join(arguments, " "), stderr)
	}
	return string(stdout)
}

func runCommand(executable, directory string, environment []string, arguments ...string) ([]byte, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Dir = directory
	command.Env = environment
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if ctx.Err() != nil {
		err = fmt.Errorf("command timeout: %w", ctx.Err())
	}
	return stdout.Bytes(), stderr.Bytes(), err
}

func assertPassingEnvelope(t *testing.T, command string, envelope cliEnvelope) {
	t.Helper()
	if envelope.SchemaVersion != cliResultSchema || envelope.Status != "pass" || envelope.PrimaryExitCode != 0 || len(envelope.Conditions) != 0 {
		t.Fatalf("%s returned a non-passing envelope: %#v", command, envelope)
	}
}

func decodeData(t *testing.T, command string, raw json.RawMessage, destination any) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(destination); err != nil {
		t.Fatalf("decode %s data: %v\n%s", command, err, raw)
	}
}

func hasCondition(conditions []cliCondition, code string) bool {
	for _, condition := range conditions {
		if condition.Code == code && condition.Message != "" {
			return true
		}
	}
	return false
}

func assertRegularFile(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat persisted run file %q: %v", path, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() == 0 {
		t.Fatalf("persisted run path is not a non-empty regular file: %q (%v)", path, info.Mode())
	}
}

func sameExistingPath(left, right string) bool {
	leftInfo, leftErr := os.Stat(left)
	rightInfo, rightErr := os.Stat(right)
	return leftErr == nil && rightErr == nil && os.SameFile(leftInfo, rightInfo)
}
