// Package contracts is the single, authoritative source of truth for the
// platform's frozen cross-service contracts. Every service imports its token
// claims, grant shapes, consent records, event payloads, and NATS subjects
// from here and never redefines them locally (CLAUDE.md: pkg/contracts is
// authoritative).
//
// The security-first design decisions encoded in this package — the token
// revocation model, global-capability claims (not per-room roles), consent
// signing over a canonical encoding, the canonical entity map, and 1:1-session
// handling — are recorded in human-readable form in docs/data-model.md.
// Threat IDs in the comments (A-1, A-3, A-5, B-2, C-4, D-2 ...) reference
// docs/threat-register.md.
//
// This package depends only on the Go standard library: it is imported by
// every service, so its dependency surface is kept at zero (E-2).
package contracts
