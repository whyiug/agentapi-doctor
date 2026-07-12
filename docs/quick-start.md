# Quick Start

[Documentation home](README.md) | [简体中文](zh-CN/quick-start.md)

Run a complete local check in about 60 seconds after the Go toolchain is ready.
The example uses a deterministic synthetic API on `127.0.0.1`, requires no
credential, and makes no request to a public endpoint.

## Prerequisites

- Git
- The Go toolchain selected by the repository's `go.mod`
- A POSIX-compatible shell (Linux, macOS, WSL, or Git Bash)

## Build and run

Use a fresh checkout because `doctor init` will not overwrite an existing
`.agentapi/config.yaml`.

```sh
git clone https://github.com/whyiug/agentapi-doctor.git
cd agentapi-doctor

mkdir -p ./bin
go build -o ./bin/doctor ./cmd/doctor
go build -o ./bin/reference-server ./cmd/reference-server

reference_log="${TMPDIR:-/tmp}/agentapi-doctor-reference.$$"
./bin/reference-server -listen 127.0.0.1:8090 >"$reference_log" 2>&1 &
reference_pid=$!
trap 'kill "$reference_pid" 2>/dev/null || true; wait "$reference_pid" 2>/dev/null || true; rm -f "$reference_log"' EXIT INT TERM
sleep 1

./bin/doctor init
./bin/doctor test local-reference
./bin/doctor report terminal latest
```

The shell trap stops only the reference process started by this session and
removes its temporary log.

## Expected result

The terminal report should include:

```text
Profile outcome: COMPATIBLE
Cases: 4 candidate / 4 applicable / 4 executed
Verdicts: PASS 4
```

The exact run ID is generated for your run. Results and evidence are stored
under `.agentapi/runs` and `.agentapi/evidence`; both paths are ignored by Git.

This result proves only that the current runner can evaluate the checked-in
synthetic fixture. It is not a compatibility claim for another endpoint and
not vendor certification.

## Next steps

- Follow [Getting Started](getting-started/README.md) to add an authorized
  target, inspect an offline plan, and export reports.
- Read [Configuration](configuration.md) before adding credentials.
- Use the [CLI reference](cli-reference.md) for every command and exit code.
- If the port is busy or initialization fails, see
  [Troubleshooting](troubleshooting.md).

The catalog contains 260 candidate metadata scenario records. The current
reference server has 12 executable targeted modes, and this quick start runs
the 4 checks selected for the `openai-responses` target.
