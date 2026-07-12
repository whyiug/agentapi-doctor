// Package driverprotocol defines AgentAPI Doctor's stable out-of-process
// driver control protocol.
//
// Control messages are JSON-RPC 2.0 objects carried as one JSON value per
// NDJSON line. Large observation payloads are carried on a separately
// negotiated, length-prefixed companion stream; drivers never mint CAS
// references themselves.
package driverprotocol
