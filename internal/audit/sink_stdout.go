package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
)

// StdoutSink writes JSONL audit events to standard output. The
// default mode in K8s deployments — cluster log shippers (Fluent
// Bit, Vector, Promtail) collect pod stdout and ship it onwards.
//
// Internally maintains its own chain state. Safe for concurrent
// Emit calls; the mutex serialises both the hash computation (so
// concurrent emits chain in a defined order) and the write itself
// (so log lines don't interleave mid-line).
type StdoutSink struct {
	mu       sync.Mutex
	lastHash *string
	writer   io.Writer
}

// NewStdoutSink constructs a sink writing to os.Stdout.
func NewStdoutSink() *StdoutSink {
	return &StdoutSink{writer: os.Stdout}
}

// newStdoutSinkTo is exported only via the test build. Lets tests
// inject an in-memory writer and inspect what got written.
func newStdoutSinkTo(w io.Writer) *StdoutSink {
	return &StdoutSink{writer: w}
}

// Emit chains the event with this sink's prev_hash state, computes
// the new event_hash, sets both fields on the event, serialises to
// JSON, and writes one line to the underlying writer.
func (s *StdoutSink) Emit(event Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	event.PrevHash = s.lastHash
	h, err := ComputeEventHash(event, s.lastHash)
	if err != nil {
		return fmt.Errorf("audit: compute hash: %w", err)
	}
	event.EventHash = h

	line, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("audit: serialise event: %w", err)
	}

	if _, err := fmt.Fprintln(s.writer, string(line)); err != nil {
		return fmt.Errorf("audit: write to stdout: %w", err)
	}

	s.lastHash = &h
	return nil
}

// Close is a no-op for stdout; included for Sink-interface compliance.
func (s *StdoutSink) Close() error {
	return nil
}
