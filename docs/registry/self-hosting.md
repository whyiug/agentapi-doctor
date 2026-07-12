# Self-hosting candidate

The repository contains a runnable **single-node development candidate** for a
self-hosted Registry. It uses one SQLite database and serves the HTTP API and
static Matrix from one process. This is not a hosted project service, a
production deployment profile, or a supported high-availability topology.

The local Doctor does not require a Registry and must continue to work when
this service is stopped or unavailable.

## Run from source

Build the exact source revision you intend to test:

```sh
install -d -m 700 ./bin ./var/registry
go build -o ./bin/registry ./cmd/registry
umask 077
export AGENTAPI_REGISTRY_TOKEN="$(openssl rand -hex 32)"
./bin/registry serve -database ./var/registry/registry.db
```

Use a secret manager or another cryptographically secure generator if
`openssl` is unavailable. Do not put the token in a command-line flag, source
file, image, Compose file, or shell history. The default listener is
`127.0.0.1:8080`. In another terminal, a read-only smoke request is:

```sh
curl --fail 'http://127.0.0.1:8080/v1/observations?limit=1'
```

The Matrix is available at `http://127.0.0.1:8080/matrix`. A fresh database has
no published observations because the hosted verifier and publication worker
are not implemented.

`-database` is required for durable mode. A relative path is resolved to an
absolute path before opening. `-allow-ephemeral` is an explicit, mutually
exclusive memory-only option for tests and short-lived development; it loses
all state on exit and is not a backup substitute.

## Run the checked-in Compose candidate

The checked-in `compose.yaml` builds the Registry image from the current
checkout:

```sh
umask 077
export AGENTAPI_REGISTRY_TOKEN="$(openssl rand -hex 32)"
docker compose up --build registry
```

Its relevant wiring is:

- SQLite database: `/data/registry.db`;
- persistent named volume: `registry-data`, mounted at `/data`;
- container listener: `0.0.0.0:8080` with the required explicit
  `-allow-non-loopback` acknowledgement; and
- host listener: `127.0.0.1:18080` by default, configurable with
  `AGENTAPI_REGISTRY_PORT` while remaining loopback-bound.

The container runs as UID/GID `65532`, with a read-only root filesystem and a
writable `/data` volume. `docker compose stop registry` preserves the named
volume. Do not use `docker compose down -v` unless permanent deletion of the
Registry volume is intended and separately authorized.

This Compose file is a local candidate, not a published or digest-pinned
Registry release bundle. It has no TLS terminator, managed secrets, monitoring,
or automated off-volume backup.

## Listener boundary

Loopback is the default and recommended development boundary. A direct
non-loopback listener is rejected unless both the address and acknowledgement
are supplied, for example:

```sh
./bin/registry serve \
  -database ./var/registry/registry.db \
  -listen 0.0.0.0:8080 \
  -allow-non-loopback
```

The acknowledgement does not add TLS, authenticate read endpoints, configure
a firewall, or make the service production-ready. Do not expose this plaintext
candidate to the public Internet. Any authorized private-network experiment
needs a separately configured TLS reverse proxy, access controls, firewall,
and backup plan. The Compose service binds inside its private container network
but publishes only to host loopback by default; changing the host-side address
changes that security boundary.

## Bearer token and TTL

The server reads a bearer token from `AGENTAPI_REGISTRY_TOKEN` by default. The
variable name can be changed with `-token-env`; the token value itself has no
CLI flag. Tokens must contain 16–4096 non-whitespace bytes. The configured
principal defaults to `local-operator` and receives the current local write
scopes for observation prepare/commit, ownership management, and disputes.

The default `-token-ttl` is eight hours. The expiry is calculated when the
process starts and the token hash is inserted or refreshed in SQLite. It is
not renewed while a long-running process stays up. Restarting with the same
token refreshes its expiry. Starting with a different token does **not** revoke
an old, unexpired token already stored in the database; there is no token
revocation command in this candidate. Use short TTLs and an isolation boundary
appropriate to that limitation.

Only a SHA-256 token hash, principal, scopes, and expiry are stored in SQLite;
the plaintext token remains process environment state. Query-string tokens are
rejected. Send write credentials only in one `Authorization: Bearer ...`
header. On a fresh database, leaving the token environment variable unset
means no write token is configured. On a reused or restored database, existing
unexpired token records remain effective even if the variable is later unset.

## What SQLite does and does not persist

The database is a regular, non-symlink file. The implementation creates parent
directories with mode `0700`, sets the database to `0600`, enables foreign-key
checks, uses WAL mode, and checkpoints WAL on a clean shutdown. While running,
SQLite may create `registry.db-wal` and `registry.db-shm` beside the main file.

The current schema persists:

- bearer-token hashes, principals, scopes, and expiries;
- ingest session snapshots, declared sizes, upload digests, and challenge
  hashes;
- parsed staged observation JSON and any published observation rows;
- ownership challenges and current ownership snapshots;
- dispute snapshots; and
- stored pack/profile documents present in the artifact table.

It does not provide an external object store or retain a separate byte-for-byte
raw upload object after parsing. Process environment, plaintext tokens, logs,
reverse-proxy configuration, image/source identity, and operator policy are
outside the database and need separate protection. The in-process rate-limit
window is also lost on restart.

Most importantly, durable SQLite storage does not implement the hosted
verifier. Observation prepare and upload can be retained, but commit reports
`501 hosted_verifier_unavailable`; no durable verification queue, automatic
publication, project trust label, or project-operated runner is implied.

## Current limitations

- single process, single SQLite writer connection, and no HA or replication;
- no TLS, SSO, token revocation UI/CLI, or fine-grained operator provisioning;
- no hosted verifier, publication worker, public runner, moderation workflow,
  or automatic trust decisions;
- no bundled monitoring, alerting, audit-log export, retention enforcement, or
  encrypted-at-rest storage;
- no stable database migration or downgrade promise beyond the checked-in
  candidate; and
- no production capacity claim, external security review, or completed
  operator recovery exercise.

Use the [backup and recovery runbook](../operations/backup-and-recovery.md)
before retaining data that would be costly to recreate.
