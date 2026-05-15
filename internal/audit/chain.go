// SHA-256 chain implementation. Must produce hashes byte-equivalent
// to aegrail-py's `aegrail.audit.compute_event_hash` so that
// `verify_chain` in the Python library validates engine-produced
// logs end-to-end.
//
// IMPLEMENTATION GOAL FOR v0.1.0: serialize the Event (excluding
// EventHash itself; explicitly including PrevHash) as canonical JSON
// with sort_keys=True equivalent, then SHA-256 the resulting bytes.
// Python's json.dumps(sort_keys=True, separators=(",", ":"))
// produces a specific byte layout; Go's encoding/json with the
// fields in dictionary order produces the same. A round-trip test
// against a Python-generated fixture confirms this.
//
// Placeholder for now — the implementation lands with the
// proxy work.

package audit

// ComputeEventHash computes the SHA-256 chain link for a given
// Event and its predecessor's hash. The result must equal what
// aegrail-py's `aegrail.audit.compute_event_hash` produces for the
// same input.
//
// PLACEHOLDER: returns an empty string. The real implementation
// lands as part of the v0.1.0 proxy work.
func ComputeEventHash(_ Event, _ *string) string {
	return ""
}

// VerifyChain walks a slice of Events and confirms each one's
// EventHash matches what ComputeEventHash would produce given the
// prior event's EventHash. Returns (true, -1) on a valid chain or
// (false, i) at the first failing index.
//
// PLACEHOLDER: returns (true, -1). The real implementation lands
// with the proxy work.
func VerifyChain(_ []Event) (bool, int) {
	return true, -1
}
