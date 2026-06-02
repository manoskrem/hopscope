package mapper

import (
	"bytes"
	"testing"
	"time"

	contractsv1 "github.com/hopscope/agent/internal/contracts/v1"
	"github.com/hopscope/agent/internal/resp"
	"google.golang.org/protobuf/proto"
)

func TestFromCommand_GoldenShape(t *testing.T) {
	m := New()
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)

	env := m.FromCommand("redis-cli", "SET", "user:1", 4242, now)

	if env.GetSource() != "redis-cli" {
		t.Errorf("Source = %q, want redis-cli", env.GetSource())
	}
	if env.GetDestination() != "user:*" {
		t.Errorf("Destination = %q, want user:*", env.GetDestination())
	}
	if env.GetBrokerType() != "Redis" {
		t.Errorf("BrokerType = %q, want Redis", env.GetBrokerType())
	}
	if env.GetExecutionStatus() != contractsv1.ExecutionStatus_SUCCESS {
		t.Errorf("ExecutionStatus = %v, want SUCCESS", env.GetExecutionStatus())
	}
	if env.GetParentHopId() != "" {
		t.Errorf("ParentHopId = %q, want empty", env.GetParentHopId())
	}
	if env.GetErrorDetails() != nil {
		t.Errorf("ErrorDetails = %v, want nil", env.GetErrorDetails())
	}
	if env.GetTraceId() != "redis-activity:redis-cli:user:*" {
		t.Errorf("TraceId = %q", env.GetTraceId())
	}

	meta := env.GetPayloadMetadata()
	wantMeta := map[string]string{
		"destinationKind": "Topic",
		"sourceKind":      "Service",
		"redisEvent":      "set",
		"keyPrefix":       "user:*",
		"db":              "0",
		"capturedBy":      "agent-ebpf",
		"clientComm":      "redis-cli",
		"pid":             "4242",
	}
	for k, want := range wantMeta {
		if got := meta[k]; got != want {
			t.Errorf("metadata[%q] = %q, want %q", k, got, want)
		}
	}
}

func TestFromCommand_FreshHopStableTrace(t *testing.T) {
	m := New()
	now := time.Now()

	a := m.FromCommand("redis-cli", "GET", "user:9", 1, now)
	b := m.FromCommand("redis-cli", "GET", "user:9", 1, now)

	if a.GetHopId() == b.GetHopId() {
		t.Errorf("HopIds must differ per observation (edge Count): %q == %q", a.GetHopId(), b.GetHopId())
	}
	if a.GetTraceId() != b.GetTraceId() {
		t.Errorf("TraceId must be stable per (source, prefix): %q != %q", a.GetTraceId(), b.GetTraceId())
	}
}

func TestFromCommand_EmptyCommFallback(t *testing.T) {
	m := New()
	// A NUL-padded / empty comm must not yield an empty Source (the engine would reject it).
	env := m.FromCommand("\x00\x00\x00", "PING", "", 0, time.Now())
	if env.GetSource() != "redis-client" {
		t.Errorf("Source = %q, want redis-client fallback", env.GetSource())
	}
	if env.GetDestination() != "keys:*" {
		t.Errorf("Destination = %q, want keys:* for keyless command", env.GetDestination())
	}
}

func TestFromError_GoldenShape(t *testing.T) {
	m := New()
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	const errLine = "WRONGTYPE Operation against a key holding the wrong kind of value"

	// parentHopID / traceID come from the correlated request (a prior LPUSH on user:1).
	env := m.FromError("redis-cli", "LPUSH", "user:1",
		"agent-redis:redis-cli:user:*:7", "redis-activity:redis-cli:user:*",
		"WRONGTYPE", errLine, 4242, now)

	if env.GetExecutionStatus() != contractsv1.ExecutionStatus_FAILED {
		t.Errorf("ExecutionStatus = %v, want FAILED", env.GetExecutionStatus())
	}
	ed := env.GetErrorDetails()
	if ed == nil {
		t.Fatal("ErrorDetails = nil, want populated")
	}
	if ed.GetExceptionType() != "WRONGTYPE" {
		t.Errorf("ExceptionType = %q, want WRONGTYPE", ed.GetExceptionType())
	}
	if ed.GetMessage() != errLine {
		t.Errorf("Message = %q, want %q", ed.GetMessage(), errLine)
	}
	if ed.GetTruncatedStackTrace() != "" {
		t.Errorf("TruncatedStackTrace = %q, want empty", ed.GetTruncatedStackTrace())
	}
	if env.GetParentHopId() != "agent-redis:redis-cli:user:*:7" {
		t.Errorf("ParentHopId = %q, want the request hopId", env.GetParentHopId())
	}
	if env.GetTraceId() != "redis-activity:redis-cli:user:*" {
		t.Errorf("TraceId = %q, want the request traceId", env.GetTraceId())
	}
	if env.GetHopId() == env.GetParentHopId() {
		t.Errorf("HopId must be fresh, not equal to ParentHopId (%q)", env.GetHopId())
	}
	if env.GetSource() != "redis-cli" || env.GetDestination() != "user:*" {
		t.Errorf("edge = %q->%q, want redis-cli->user:*", env.GetSource(), env.GetDestination())
	}

	meta := env.GetPayloadMetadata()
	if meta["redisError"] != errLine {
		t.Errorf("metadata[redisError] = %q, want %q", meta["redisError"], errLine)
	}
	wantMeta := map[string]string{
		"destinationKind": "Topic",
		"sourceKind":      "Service",
		"redisEvent":      "lpush",
		"keyPrefix":       "user:*",
		"db":              "0",
		"capturedBy":      "agent-ebpf",
		"clientComm":      "redis-cli",
		"pid":             "4242",
	}
	for k, want := range wantMeta {
		if got := meta[k]; got != want {
			t.Errorf("metadata[%q] = %q, want %q", k, got, want)
		}
	}
}

// TestFromError_SameEdgeAsCommand proves a captured error lands on the SAME source->dest edge
// (and trace) as the request it correlates to, so the canvas turns that one edge red and the
// drill-down groups request -> error.
func TestFromError_SameEdgeAsCommand(t *testing.T) {
	m := New()
	now := time.Now()

	cmd := m.FromCommand("redis-cli", "LPUSH", "user:1", 1, now)
	err := m.FromError("redis-cli", "LPUSH", "user:1",
		cmd.GetHopId(), cmd.GetTraceId(), "WRONGTYPE", "WRONGTYPE ...", 1, now)

	if err.GetSource() != cmd.GetSource() {
		t.Errorf("Source mismatch: %q vs %q", err.GetSource(), cmd.GetSource())
	}
	if err.GetDestination() != cmd.GetDestination() {
		t.Errorf("Destination mismatch: %q vs %q", err.GetDestination(), cmd.GetDestination())
	}
	if err.GetTraceId() != cmd.GetTraceId() {
		t.Errorf("TraceId mismatch: %q vs %q", err.GetTraceId(), cmd.GetTraceId())
	}
	if err.GetParentHopId() != cmd.GetHopId() {
		t.Errorf("error ParentHopId %q should link to the request HopId %q", err.GetParentHopId(), cmd.GetHopId())
	}
}

// TestPipelineErrorPrivacy is the recv-side body-free assertion across resp + mapper: a real
// -WRONGTYPE reply, parsed and mapped to a Failed envelope, carries the broker's error line but
// no business value, even when the captured prefix includes a pipelined success value.
func TestPipelineErrorPrivacy(t *testing.T) {
	const secret = "supersecretvalue"
	// The kernel only submits recv buffers whose first byte is '-'; the captured prefix may
	// still include trailing bytes of a pipelined success reply carrying the value.
	buf := []byte("-WRONGTYPE Operation against a key holding the wrong kind of value\r\n$16\r\n" + secret + "\r\n")

	code, line, ok := resp.ParseError(buf)
	if !ok {
		t.Fatal("ParseError failed on a real error reply")
	}
	env := New().FromError("redis-cli", "LPUSH", "user:1",
		"agent-redis:redis-cli:user:*:1", "redis-activity:redis-cli:user:*", code, line, 7, time.Now())

	blob, err := proto.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(blob, []byte(secret)) {
		t.Fatalf("value %q leaked into the serialized Failed envelope", secret)
	}
	if !bytes.Contains(blob, []byte("WRONGTYPE")) {
		t.Fatal("the error code/line should be present in the envelope (it is broker diagnostic text)")
	}
}

// TestPipelinePrivacy is the end-to-end body-free assertion across resp + mapper:
// a real SET with a secret value, parsed and mapped, must not contain the value
// anywhere in the serialized envelope.
func TestPipelinePrivacy(t *testing.T) {
	const secret = "supersecretvalue"
	buf := []byte("*3\r\n$3\r\nSET\r\n$6\r\nuser:1\r\n$16\r\n" + secret + "\r\n")

	verb, key, ok := resp.Parse(buf)
	if !ok {
		t.Fatal("parse failed")
	}
	env := New().FromCommand("redis-cli", verb, key, 7, time.Now())

	blob, err := proto.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(blob, []byte(secret)) {
		t.Fatalf("value %q leaked into the serialized envelope", secret)
	}
}
