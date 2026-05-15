// Sink contract for emitting audit events. Each Sink implementation
// is responsible for: (1) maintaining the prev_hash chain state
// across emit calls (so consumers don't need to), (2) writing the
// resulting Event in JSONL form to its underlying transport,
// (3) being safe for concurrent Emit calls from multiple goroutines.
//
// IMPLEMENTATIONS for v0.1.0:
//   - StdoutSink: JSONL to os.Stdout, mutex-protected, flushed per
//     event. Default mode; cluster log shippers collect it.
//   - FileSink: append-only JSONL to a file path, with chain
//     recovery on open (read last line, parse event_hash, use as
//     starting prev_hash). Mirrors aegrail-py's FileAuditSink.
//
// Placeholder file for now — the interface is settled; the
// concrete implementations land with the proxy work.

package audit

// Sink is what the proxy emits audit events through. Implementations
// own the chain state for their underlying transport.
type Sink interface {
	// Emit writes one event to the underlying transport. The Sink
	// is responsible for setting PrevHash and EventHash on the
	// event using its internal chain state. Implementations MUST
	// be safe for concurrent calls.
	Emit(event Event) error

	// Close releases any resources held by the sink. Idempotent.
	// For sinks that buffer (file, network), Close flushes
	// outstanding writes.
	Close() error
}
