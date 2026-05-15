package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// -- StdoutSink -----------------------------------------------------

func TestStdoutSink_EmitsJSONLWithChainFields(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	sink := newStdoutSinkTo(&buf)

	for i := 0; i < 3; i++ {
		event := Event{
			Ts:            "2026-05-15T09:42:11.123Z",
			SessionID:     "sess_stdout",
			AgentIdentity: "test/v1",
			Principal:     "test/v1@sess_stdout",
			EventType:     "engine_start",
			Payload:       map[string]any{"step": i},
			Budget:        map[string]any{},
		}
		if err := sink.Emit(event); err != nil {
			t.Fatalf("Emit %d: %v", i, err)
		}
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}

	events := make([]Event, 0, 3)
	for i, line := range lines {
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("line %d not valid JSON: %v\n%s", i, err, line)
		}
		if e.EventHash == "" {
			t.Errorf("line %d: event_hash is empty", i)
		}
		events = append(events, e)
	}

	// Genesis event has nil prev_hash
	if events[0].PrevHash != nil {
		t.Errorf("genesis event prev_hash should be nil, got %q", *events[0].PrevHash)
	}
	// Subsequent events chain
	for i := 1; i < len(events); i++ {
		if events[i].PrevHash == nil || *events[i].PrevHash != events[i-1].EventHash {
			t.Errorf("chain broken at line %d", i)
		}
	}

	ok, bad, err := VerifyChain(events)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !ok {
		t.Errorf("StdoutSink chain failed verify at index %d", bad)
	}
}

func TestStdoutSink_ConcurrentEmitSerialisesCorrectly(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	sink := newStdoutSinkTo(&buf)

	const N = 50
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			event := Event{
				Ts:            "2026-05-15T09:42:11.123Z",
				SessionID:     "sess_concurrent",
				AgentIdentity: "test/v1",
				Principal:     "test/v1@sess_concurrent",
				EventType:     "engine_start",
				Payload:       map[string]any{"goroutine": i},
				Budget:        map[string]any{},
			}
			if err := sink.Emit(event); err != nil {
				t.Errorf("Emit: %v", err)
			}
		}(i)
	}
	wg.Wait()

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != N {
		t.Fatalf("expected %d lines, got %d", N, len(lines))
	}
	events := make([]Event, 0, N)
	for i, line := range lines {
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("line %d not valid JSON: %v", i, err)
		}
		events = append(events, e)
	}
	ok, bad, err := VerifyChain(events)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !ok {
		t.Errorf("concurrent emits broke the chain at index %d", bad)
	}
}

func TestStdoutSink_CloseIsNoop(t *testing.T) {
	t.Parallel()
	sink := NewStdoutSink()
	if err := sink.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// -- FileSink -------------------------------------------------------

func TestFileSink_EmitsJSONLToFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	defer sink.Close()

	for i := 0; i < 3; i++ {
		event := Event{
			Ts:            "2026-05-15T09:42:11.123Z",
			SessionID:     "sess_file",
			AgentIdentity: "test/v1",
			Principal:     "test/v1@sess_file",
			EventType:     "engine_start",
			Payload:       map[string]any{"step": i},
			Budget:        map[string]any{},
		}
		if err := sink.Emit(event); err != nil {
			t.Fatalf("Emit %d: %v", i, err)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d:\n%s", len(lines), string(data))
	}

	events := parseEvents(t, lines)
	ok, bad, err := VerifyChain(events)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !ok {
		t.Errorf("FileSink chain broken at index %d", bad)
	}
}

func TestFileSink_ChainContinuesAcrossOpens(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// First lifetime: emit 2 events
	sink1, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := sink1.Emit(testEvent("sess_a", i)); err != nil {
			t.Fatalf("first emit %d: %v", i, err)
		}
	}
	if err := sink1.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}

	// Second lifetime: reopen the same file, emit 2 more events.
	// The chain must continue — second sink's first event's
	// prev_hash should equal first sink's last event's event_hash.
	sink2, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := sink2.Emit(testEvent("sess_b", i)); err != nil {
			t.Fatalf("second emit %d: %v", i, err)
		}
	}
	if err := sink2.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 4 {
		t.Fatalf("expected 4 total lines, got %d", len(lines))
	}
	events := parseEvents(t, lines)
	ok, bad, err := VerifyChain(events)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !ok {
		t.Errorf("chain broken across process restart at index %d", bad)
	}
}

func TestFileSink_EmptyExistingFileIsGenesis(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// Touch an empty file
	if err := os.WriteFile(path, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}

	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	defer sink.Close()

	if err := sink.Emit(testEvent("sess", 0)); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	data, _ := os.ReadFile(path)
	var e Event
	if err := json.Unmarshal(bytes.TrimSpace(data), &e); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.PrevHash != nil {
		t.Errorf("empty file should start a new genesis chain; got prev_hash=%q", *e.PrevHash)
	}
}

func TestFileSink_MissingDirectoryIsCreated(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	deep := filepath.Join(dir, "nested", "deeper")
	path := filepath.Join(deep, "audit.jsonl")

	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	defer sink.Close()

	if err := sink.Emit(testEvent("sess", 0)); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("file not created at %s: %v", path, err)
	}
}

func TestFileSink_MalformedLineSkippedDuringRecovery(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// Pre-populate with one valid and one malformed line
	sink1, err := NewFileSink(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink1.Emit(testEvent("sess", 0)); err != nil {
		t.Fatal(err)
	}
	if err := sink1.Close(); err != nil {
		t.Fatal(err)
	}
	// Append a corrupted line
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("not-json-at-all\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen — recovery should skip the malformed line and pick up
	// the chain from the last valid event_hash.
	sink2, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("recover from corrupted: %v", err)
	}
	if err := sink2.Emit(testEvent("sess", 1)); err != nil {
		t.Fatalf("Emit after recovery: %v", err)
	}
	if err := sink2.Close(); err != nil {
		t.Fatal(err)
	}

	// The new event's prev_hash should reference the first event's
	// event_hash (skipping the corrupted line entirely).
	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var first, last Event
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("first line parse: %v", err)
	}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &last); err != nil {
		t.Fatalf("last line parse: %v", err)
	}
	if last.PrevHash == nil || *last.PrevHash != first.EventHash {
		t.Errorf("recovery failed to skip malformed line: last.prev_hash=%v, first.event_hash=%v",
			last.PrevHash, first.EventHash)
	}
}

func TestFileSink_CloseIsIdempotent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Errorf("second Close should be no-op: %v", err)
	}
}

func TestFileSink_EmitAfterCloseErrors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	err = sink.Emit(testEvent("sess", 0))
	if err == nil {
		t.Error("Emit after Close should return an error")
	}
}

// -- helpers --------------------------------------------------------

func testEvent(session string, step int) Event {
	return Event{
		Ts:            "2026-05-15T09:42:11.123Z",
		SessionID:     session,
		AgentIdentity: "test/v1",
		Principal:     "test/v1@" + session,
		EventType:     "engine_start",
		Payload:       map[string]any{"step": step},
		Budget:        map[string]any{},
	}
}

func parseEvents(t *testing.T, lines []string) []Event {
	t.Helper()
	out := make([]Event, 0, len(lines))
	for i, line := range lines {
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("parse line %d: %v\n%s", i, err, line)
		}
		out = append(out, e)
	}
	return out
}
