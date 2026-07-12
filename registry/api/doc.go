// Package api contains transport-neutral public Registry contracts.
//
// The package intentionally does not perform network I/O or persistence.  In
// particular, an attestation URI is data only; consumers must not fetch it
// without applying their own allowlist and network policy.
package api
