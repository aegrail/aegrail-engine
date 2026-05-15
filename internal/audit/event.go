// Package audit implements the SHA-256-chained audit log emitted by
// the aegrail engine. The on-the-wire format is identical to the
// aegrail Python library's `AuditEvent`: same JSON shape, same field
// ordering for hash computation, same chain semantics. A downstream
// consumer can run `aegrail.audit.verify_chain()` from the Python
// library over engine-produced logs and it MUST validate end-to-end.
//
// Implementation lands in v0.1.0. This file establishes the type
// contract that the proxy and CLI will write through.
package audit

// Event is the on-the-wire JSON shape of one audit record. Fields
// match the aegrail Python library's AuditEvent exactly so that
// chains spanning both producers verify with one tool.
//
// The implementation in v0.1.0 will populate this struct, compute
// EventHash via the same SHA-256 algorithm as aegrail-py, and write
// the JSON-encoded form to the configured sink.
type Event struct {
	Ts            string         `json:"ts"`
	SessionID     string         `json:"session_id"`
	AgentIdentity string         `json:"agent_identity"`
	InvokingUser  *string        `json:"invoking_user"`
	Principal     string         `json:"principal"`
	EventType     string         `json:"event"`
	Payload       map[string]any `json:"payload"`
	Budget        map[string]any `json:"budget"`
	PrevHash      *string        `json:"prev_hash"`
	EventHash     string         `json:"event_hash"`
}

// EventType constants. These mirror the aegrail Python library's
// EventType literal so cross-language consumers can match on the
// same set of values.
const (
	TypeEngineStart     = "engine_start"
	TypeEngineShutdown  = "engine_shutdown"
	TypeEngineHeartbeat = "engine_heartbeat"
	TypeEgressAllowed   = "egress_allowed"
	TypeEgressDenied    = "egress_denied"
	TypeEgressError     = "egress_error"
)
