// session.go: per-engine-process session identity for audit events.
//
// The aegrail Python library audits events under a per-Session
// principal of the form `<agent_identity>@sess_<unix-ms>_<rand>`.
// The engine adopts the same convention so chains produced by the
// engine are byte-compatible with chains produced by the Python
// library; downstream tooling (Athena queries, Splunk dashboards)
// doesn't have to special-case proxy events.
//
// One Session is constructed at engine startup and used for the
// process lifetime. Restart = new session_id. The audit chain
// continues across restarts via FileSink's recovery, but the
// session_id changes — which is the right granularity for forensic
// analysis ("which engine process emitted these events?").

package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// Session is the immutable principal context the proxy stamps on
// every audit event it emits.
type Session struct {
	AgentIdentity string
	SessionID     string
}

// NewSession constructs a session with a freshly minted session id
// in the same shape as the aegrail Python library:
// `sess_<unix-millis>_<8-hex-bytes-random>`.
func NewSession(agentIdentity string) (*Session, error) {
	var randBytes [8]byte
	if _, err := rand.Read(randBytes[:]); err != nil {
		return nil, fmt.Errorf("proxy: generate session randomness: %w", err)
	}
	id := fmt.Sprintf(
		"sess_%d_%s",
		time.Now().UnixMilli(),
		hex.EncodeToString(randBytes[:]),
	)
	return &Session{
		AgentIdentity: agentIdentity,
		SessionID:     id,
	}, nil
}

// Principal returns the `<agent_identity>@<session_id>` string used
// as the Principal field on every audit event.
func (s *Session) Principal() string {
	return s.AgentIdentity + "@" + s.SessionID
}
