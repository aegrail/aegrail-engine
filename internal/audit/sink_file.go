package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// FileSink writes JSONL events to a local file in append-only mode.
// On open, it reads the existing file (if any) and recovers the last
// event's event_hash, then continues the chain from there. A single
// audit file written by many process lifetimes remains one verifiable
// chain — matching aegrail-py's FileAuditSink behavior exactly.
//
// Thread-safe; concurrent Emit calls serialise through the same
// mutex.
type FileSink struct {
	mu       sync.Mutex
	lastHash *string
	f        *os.File
}

// NewFileSink opens (or creates) the file at path. If the file
// exists and is non-empty, the constructor reads it forward and
// initialises the chain state from the last valid line's event_hash
// — so the chain spans process restarts. Parent directories are
// created as needed.
//
// Malformed lines in the existing file are skipped silently during
// recovery. The latest valid `event_hash` wins. This matches the
// Python library's resilience to partial writes or operator edits.
func NewFileSink(path string) (*FileSink, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("audit: mkdir parents: %w", err)
	}

	lastHash, err := readLastEventHash(path)
	if err != nil {
		return nil, fmt.Errorf("audit: recover chain state: %w", err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("audit: open file: %w", err)
	}

	return &FileSink{f: f, lastHash: lastHash}, nil
}

// Emit chains the event, computes its hash, serialises to JSON, and
// appends one line. Calls fsync after each write so kernel crashes
// don't lose audit records.
func (s *FileSink) Emit(event Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return fmt.Errorf("audit: file sink is closed")
	}

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

	if _, err := fmt.Fprintln(s.f, string(line)); err != nil {
		return fmt.Errorf("audit: write to file: %w", err)
	}

	if err := s.f.Sync(); err != nil {
		// fsync failure is loud — surface it. Audit reliability
		// requires durability; if the kernel can't commit, callers
		// should know.
		return fmt.Errorf("audit: fsync: %w", err)
	}

	s.lastHash = &h
	return nil
}

// Close flushes and closes the underlying file. Idempotent.
func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}

// readLastEventHash scans the file forward, returning the
// event_hash from the last syntactically-valid JSON line. Returns
// (nil, nil) for missing or empty files. Used by NewFileSink to
// continue a chain across process restarts.
//
// Forward scan is O(n) in file size. For audit files that grow to
// hundreds of MB, this becomes slow at startup. A future
// optimisation would seek to end and read backward to the previous
// newline — deferred to a v0.2.0 milestone when real users hit the
// scale that requires it.
func readLastEventHash(path string) (*string, error) {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if info.Size() == 0 {
		return nil, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// 16 MiB max line — generous for any reasonable audit event.
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 16*1024*1024)

	var lastHash *string
	for scanner.Scan() {
		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}
		var record struct {
			EventHash string `json:"event_hash"`
		}
		if err := json.Unmarshal(raw, &record); err != nil {
			// Skip malformed line; keep scanning. A partial write
			// at the end of a previous process should not prevent
			// chain recovery from earlier-valid records.
			continue
		}
		if record.EventHash != "" {
			h := record.EventHash
			lastHash = &h
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lastHash, nil
}
