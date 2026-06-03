package correlate

import "testing"

func req(verb, key string) Request {
	return Request{Verb: verb, FirstKey: key, Comm: "redis-cli", PID: 1,
		HopID: "hop-" + verb + "-" + key, TraceID: "trace-" + key}
}

func TestRememberThenTakeRoundTrips(t *testing.T) {
	tr := New(16)
	want := req("GET", "user:1")
	tr.Remember(42, want)

	got, ok := tr.Take(42)
	if !ok {
		t.Fatal("Take(42) found=false, want true")
	}
	if got != want {
		t.Fatalf("Take returned %+v, want %+v", got, want)
	}
}

func TestTakeUnknownSocket(t *testing.T) {
	tr := New(16)
	if _, ok := tr.Take(999); ok {
		t.Fatal("Take on an unknown socket returned found=true, want false")
	}
}

func TestRememberLastWriterWinsPerSocket(t *testing.T) {
	tr := New(16)
	tr.Remember(7, req("SET", "k"))
	tr.Remember(7, req("LPUSH", "k")) // same socket → newest request wins

	got, ok := tr.Take(7)
	if !ok {
		t.Fatal("Take(7) found=false, want true")
	}
	if got.Verb != "LPUSH" {
		t.Fatalf("Take returned verb %q, want LPUSH (last writer should win)", got.Verb)
	}
}

func TestTakeIsNonDestructive(t *testing.T) {
	tr := New(16)
	tr.Remember(5, req("GET", "a"))
	if _, ok := tr.Take(5); !ok {
		t.Fatal("first Take(5) found=false")
	}
	// Redis is request/reply-ordered, but a reply that arrives split must still correlate;
	// Take leaves the entry so a follow-up lookup on the same request succeeds.
	if _, ok := tr.Take(5); !ok {
		t.Fatal("second Take(5) found=false — Take should be non-destructive")
	}
}

func TestBoundedEvictsOldestKeepsRecent(t *testing.T) {
	const max = 4
	tr := New(max)
	// Insert far more distinct sockets than the cap.
	for s := uint64(1); s <= 12; s++ {
		tr.Remember(s, req("GET", "k"))
	}

	// The most recent insert must always survive.
	if _, ok := tr.Take(12); !ok {
		t.Fatal("most-recent socket 12 was evicted, want retained")
	}
	// A socket far older than the 2×cap window must have been evicted.
	if _, ok := tr.Take(1); ok {
		t.Fatal("oldest socket 1 survived, want evicted (bound is ~2×cap)")
	}
	// The tracker must never hold more than 2×cap entries.
	if n := tr.Len(); n > 2*max {
		t.Fatalf("Len() = %d, want <= %d (memory must stay bounded)", n, 2*max)
	}
}
