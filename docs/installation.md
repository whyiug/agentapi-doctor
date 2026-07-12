# Installation

[Documentation home](README.md)

AgentAPI Doctor currently ships as source only. There is no tagged release,
published GitHub Release archive, GHCR image, Homebrew tap, Scoop bucket, or
other supported package channel. Do not treat files under `integrations/` or
the release workflow as published artifacts.

## Requirements

- Git
- The Go toolchain selected by `go.mod` (currently Go 1.26.5)
- GNU Make and Python 3 for the complete contributor checks
- Docker only for local container images or the Compose services

The repository commits its Go vendor tree, so normal source builds do not need
to resolve Go modules from the network after the repository and required Go
toolchain are available.

## Build the CLI from source

```sh
git clone https://github.com/whyiug/agentapi-doctor.git
cd agentapi-doctor

mkdir -p ./bin
go build -trimpath -o ./bin/doctor ./cmd/doctor
./bin/doctor version
```

On Windows PowerShell, use an `.exe` output name:

```powershell
New-Item -ItemType Directory -Force .\bin | Out-Null
go build -trimpath -o .\bin\doctor.exe ./cmd/doctor
.\bin\doctor.exe version
```

To build the local reference server and self-hosted Registry as well:

```sh
go build -trimpath -o ./bin/reference-server ./cmd/reference-server
go build -trimpath -o ./bin/registry ./cmd/registry
```

`make build` compile-checks all supported commands but does not install them
or place executables in `./bin`.

## Build a local Docker image

The Dockerfile contains separate `doctor`, `registry`, and
`reference-server` targets. Build and inspect the CLI image locally:

```sh
docker build --network=none --target doctor --tag agentapi-doctor:local .
docker run --rm --network=none --read-only --cap-drop ALL \
  --security-opt no-new-privileges \
  agentapi-doctor:local version --json
```

The image runs as an unprivileged user and uses `doctor` as its entrypoint.
`agentapi-doctor:local` is a local tag, not an official published image.

For a bounded build-and-smoke check of all three image targets:

```sh
make docker-check
```

That target creates uniquely named local images and removes the images it
created when the check exits.

## Start the local Compose services

`compose.yaml` starts the Registry and synthetic reference server, not the
`doctor` CLI:

```sh
docker compose up --build registry reference
```

The host bindings are loopback-only by default:

- Registry: `127.0.0.1:18080`
- Synthetic reference server: `127.0.0.1:18090`

Override the host ports with `AGENTAPI_REGISTRY_PORT` and
`AGENTAPI_REFERENCE_PORT`. Stop only this project's services with:

```sh
docker compose down
```

See [Registry self-hosting](registry/self-hosting.md) before enabling writes or
persisting local observations.

## Verify a future release

When a release is eventually published, install only an exact version after
verifying its signature, checksum, provenance, and platform archive. The
candidate packaging files deliberately contain no usable current version or
checksum.

The verification procedure is documented in
[Release verification](operations/release-verification.md). Until an actual
release page contains the named assets, continue to build from source.

## Remove a source build

A source build does not modify system directories. Remove only the exact
executables or local image tags you created. Local runs are stored under the
working directory's `.agentapi/` tree; inspect or archive them before deleting
that directory.
