// SHA-256 chain implementation. Produces hashes byte-equivalent to
// aegrail-py's `aegrail.audit.compute_event_hash` so that
// `verify_chain` in the Python library validates engine-produced
// logs end-to-end.
//
// THE ALGORITHM (must match Python verbatim):
//
//  1. Build the canonical body: every event field EXCEPT event_hash,
//     with prev_hash explicitly set from the parameter (overriding
//     whatever may be on the event struct).
//
//  2. Serialize the body to JSON using Python's
//     `json.dumps(body, sort_keys=True, separators=(",", ":"))`
//     semantics:
//       - keys sorted lexicographically at every level
//       - no whitespace between separators
//       - HTML-special chars (<, >, &) NOT escaped (matches Python's
//         default; Go's encoding/json escapes them by default — we
//         use SetEscapeHTML(false) to match)
//       - Non-ASCII Unicode characters: this implementation matches
//         Python's `ensure_ascii=True` default (escapes as \uXXXX).
//         For audit payloads that contain non-ASCII content (rare in
//         practice — hostnames and identifiers are ASCII), see the
//         note in canonical.go about escapeNonASCII.
//
//  3. SHA-256 the resulting bytes, lowercase hex digest.
//
// Byte-equivalence with the Python implementation is verified by
// the cross-language compat test in chain_compat_test.go.

package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// ComputeEventHash returns the lowercase-hex SHA-256 digest of the
// canonical serialization of `event` (with prev_hash overridden from
// the parameter and event_hash excluded). The return value MUST
// match `aegrail.audit.compute_event_hash` in the Python library
// for the same logical input.
func ComputeEventHash(event Event, prevHash *string) (string, error) {
	// Build the canonical body. event_hash is intentionally absent;
	// prev_hash always comes from the parameter so re-hashing an
	// already-chained event with a different prev yields a
	// different hash (which is the whole point of a chain link).
	body := map[string]any{
		"ts":             event.Ts,
		"session_id":     event.SessionID,
		"agent_identity": event.AgentIdentity,
		"invoking_user":  event.InvokingUser,
		"principal":      event.Principal,
		"event":          event.EventType,
		"payload":        normalisePayload(event.Payload),
		"budget":         normalisePayload(event.Budget),
		"prev_hash":      prevHash,
	}

	payload, err := canonicalJSON(body)
	if err != nil {
		return "", fmt.Errorf("audit: canonical JSON encode failed: %w", err)
	}

	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

// VerifyChain walks `events` in order and confirms each one's
// EventHash matches what ComputeEventHash produces for that event
// using the prior event's EventHash as prev. Returns (true, -1) on
// a valid chain; (false, i) at the first failing index. Mirrors the
// semantics of `aegrail.audit.verify_chain` in the Python library.
func VerifyChain(events []Event) (bool, int, error) {
	var prev *string
	for i, e := range events {
		expected, err := ComputeEventHash(e, prev)
		if err != nil {
			return false, i, err
		}
		if e.EventHash != expected {
			return false, i, nil
		}
		// Advance the chain — copy the value so subsequent
		// iterations have a stable pointer.
		h := e.EventHash
		prev = &h
	}
	return true, -1, nil
}

// normalisePayload returns nil for nil input and the map itself
// otherwise. This handles the Python<->Go gap where Python's
// json.dumps({"payload": None}) produces `"payload":null` whereas
// Go's json.Marshal of map["payload"] = nil also produces null —
// but a Go map[string]any that is literally `nil` (not just empty)
// would also marshal as `null` rather than `{}`. We force an empty
// map to be serialized as `{}` for parity with the Python library's
// `Field(default_factory=dict)` defaults.
func normalisePayload(p map[string]any) map[string]any {
	if p == nil {
		// Python's Pydantic model defaults to {} via
		// Field(default_factory=dict). Match that.
		return map[string]any{}
	}
	return p
}
