# Backup and recovery

This runbook applies only to the current single-node SQLite self-host
candidate. It is an operator procedure, not evidence that the project has
completed a production restore exercise. No hosted Registry RPO, RTO,
retention, encryption, or on-call commitment is claimed.

## Backup scope

`registry backup` creates a transactionally consistent, standalone SQLite file
with `VACUUM INTO`. It may run while the Registry is serving requests. The
source must be an existing regular, non-symlink file. The output path must be
different and must not already exist; its parent is created with mode `0700`
and the backup is set to `0600`.

Run the backup subcommand from the same exact build as the deployed service.
Opening a database runs that build's schema check/migration path, so using a
newer backup binary against an older live database can itself change the
database before copying it.

For a source checkout build:

```sh
install -d -m 700 ./backups
./bin/registry backup \
  -database ./var/registry/registry.db \
  -output ./backups/registry-20260712T120000Z.db
sha256sum ./backups/registry-20260712T120000Z.db \
  > ./backups/registry-20260712T120000Z.db.sha256
```

Choose a new timestamped output name for every run. Never overwrite the last
known-good backup. Store the database and its digest in an access-controlled,
off-host location according to the operator's retention and encryption policy.

For the checked-in Compose candidate, `/data` is the `registry-data` named
volume and the live database is `/data/registry.db`:

```sh
install -d -m 700 ./backups
docker compose run --rm --no-deps registry backup \
  -database /data/registry.db \
  -output /data/backups/registry-20260712T120000Z.db
docker compose cp \
  registry:/data/backups/registry-20260712T120000Z.db \
  ./backups/registry-20260712T120000Z.db
```

The first command alone leaves the backup in the same named volume and
therefore does not protect against volume or host loss. Confirm the exported
copy and hash it outside the volume. Compose's scratch-based Registry image has
no shell or general-purpose restore utility.

The SQLite backup includes token hashes and expiries, ingest and staged
observation state, published rows already present, ownership records,
disputes, and stored pack/profile documents. It does not include plaintext
tokens, environment variables, service logs, TLS/reverse-proxy configuration,
Compose source, image digest, or off-database operator records. Back those up
separately without copying plaintext secrets into the repository.

## Verify every backup copy

Perform checks on a disposable copy, not on the only backup:

1. Verify the recorded SHA-256 digest after every transfer.
2. Confirm the file is regular, is not a symlink, is owned by the intended
   service/operator account, and is mode `0600`.
3. With a trusted local SQLite CLI, run:

   ```sh
   sqlite3 ./restore-check.db 'PRAGMA integrity_check;'
   sqlite3 ./restore-check.db 'PRAGMA foreign_key_check;'
   sqlite3 ./restore-check.db 'PRAGMA user_version;'
   ```

   `integrity_check` must return `ok`; `foreign_key_check` must return no rows.
   Record the schema version expected by the exact source commit or image under
   test. The current candidate schema is version 1, but that number is not a
   forward migration promise.
4. Start the exact Registry version against another disposable copy on a
   different loopback port:

   ```sh
   chmod 600 ./restore-check.db
   env -u AGENTAPI_REGISTRY_TOKEN ./bin/registry serve \
     -database ./restore-check.db \
     -listen 127.0.0.1:18081
   ```

   In another terminal, request
   `http://127.0.0.1:18081/v1/observations?limit=1` and any known, non-sensitive
   observation/dispute identifiers selected for the drill. Stop the process
   cleanly afterward.

Unsetting the token variable during this smoke test prevents startup from
adding or refreshing a token, but it does not remove unexpired token hashes
already restored from SQLite. Keep the test listener on loopback. The project
does not yet provide a full application-level command that walks every row and
recomputes every observation or artifact digest; SQLite checks alone therefore
do not prove all semantic content is valid.

## Offline restore

Restore is a stopped-service operation even though backup can be online:

1. Record the deployed source commit or image digest, flags, token-variable
   name, database path, file ownership, and expected backup digest.
2. Stop the Registry and confirm no process is writing the database. For
   Compose use `docker compose stop registry`, not `down -v`.
3. Preserve the current `registry.db`, `registry.db-wal`, and
   `registry.db-shm` together under an incident-specific name. Never combine a
   restored standalone database with stale WAL/SHM files.
4. Verify the selected backup as described above.
5. Copy it to a temporary file in the destination directory, set the service
   owner and mode `0600`, then atomically rename it to the configured
   `registry.db` path on the same filesystem. Keep the parent directory mode
   `0700`.
6. Start the same Registry version that was used before the backup first. Keep
   it loopback-bound and inspect startup errors before allowing writes.
7. Repeat the read-only smoke checks, inspect known records, and confirm the
   expected token-expiry behavior. Only then restore the intended private
   network or reverse-proxy path.
8. Retain the failed database set and the source backup unchanged until the
   recovery is accepted.

For the Compose named volume, use an operator-controlled Docker volume restore
procedure while the service is stopped. It must preserve UID/GID `65532`, file
mode `0600`, and the `/data/registry.db` path. A blind host copy or
`docker compose cp` can produce ownership that the non-root scratch container
cannot repair; verify ownership explicitly before starting it.

Restoring a database also restores its unexpired token hashes. Supplying the
configured token at startup refreshes that token's expiry; supplying a new
token does not immediately revoke old hashes. If credential compromise is part
of the incident, isolate the listener and account for the configured TTL. This
candidate has no supported token-revocation command.

## Upgrade and rollback

Treat every source revision or image change as a possible database migration:

1. Record the old binary/source or image digest and configuration.
2. Create, export, hash, and verify a pre-upgrade backup.
3. Test the new version against a disposable copy of that backup. Opening a
   database may apply a forward migration; never use the only backup for this
   test.
4. Stop the service and take a final backup after writes have ceased.
5. Start the exact new build against the live database, still on loopback.
6. Check logs, SQLite integrity/schema, the Matrix, list/read endpoints, and a
   bounded set of known records before restoring access.

If rollback is required, do not point an older binary at a database already
touched by a newer schema. Stop the service, preserve the failed upgraded
database and its WAL/SHM files, deploy the recorded old build/configuration,
and restore the pre-upgrade backup using the offline procedure. There is no
general down-migration command or compatibility guarantee in the current
candidate.

## Recovery exercise checklist

A useful local exercise should retain evidence of:

- exact source/image and configuration identity;
- backup start/end time, byte size, and SHA-256 digest;
- off-volume transfer and access-control verification;
- SQLite integrity, foreign-key, and schema results;
- restored file path, owner, and permissions;
- read-only checks of representative records and pagination;
- token-expiry and listener-isolation observations;
- measured recovery time and any accepted data-loss window; and
- cleanup that preserves the original backup and removes disposable copies.

No production recovery drill, external operational review, RPO/RTO validation,
or hosted-region failure exercise has been completed by the project. Operators
must set and test their own requirements before relying on this candidate.
