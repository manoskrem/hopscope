// Package correlate matches a Redis error reply back to the request that caused it.
//
// The agent's eBPF capture tags every event with an opaque per-socket id and a direction
// (send vs. recv-error). Because Redis is request/reply-ordered on a connection, the error
// reply on a socket belongs to the last request seen on that same socket. The kernel stays
// dumb (it only copies bytes); this package holds the small amount of per-socket state needed
// to attribute an error to its request — entirely in user space, where it is unit-testable.
//
// Concurrency: a Tracker is NOT safe for concurrent use. It is driven solely from the single
// ring-buffer Run goroutine (one Remember/Take per captured event, in order), so it needs no
// lock. Do not share a Tracker across goroutines.
package correlate

// Request is the request context remembered for a socket, used to label the Failed envelope
// when that socket's reply turns out to be an error. It never holds a Redis value.
type Request struct {
	Verb     string
	FirstKey string
	Comm     string
	PID      uint32
	HopID    string
	TraceID  string
}

// Tracker remembers the most recent request per socket, bounded so a flood of short-lived
// connections cannot grow it without limit. It uses a two-generation map: when the live
// generation fills to maxPerGen, it is demoted to "old" and a fresh live map starts; lookups
// check live then old. This caps memory at ~2×maxPerGen with O(1) work and no per-key
// bookkeeping, while still resolving the common case (reply right after request).
type Tracker struct {
	maxPerGen int
	live      map[uint64]Request
	old       map[uint64]Request
}

// New returns a Tracker bounded to roughly 2×maxPerGen live entries. maxPerGen is clamped to
// at least 1.
func New(maxPerGen int) *Tracker {
	if maxPerGen < 1 {
		maxPerGen = 1
	}
	return &Tracker{
		maxPerGen: maxPerGen,
		live:      make(map[uint64]Request, maxPerGen),
		old:       make(map[uint64]Request),
	}
}

// Remember records r as the most recent request on sockID (last writer wins). When the live
// generation is full it rotates, evicting the oldest generation.
func (t *Tracker) Remember(sockID uint64, r Request) {
	if _, inLive := t.live[sockID]; !inLive && len(t.live) >= t.maxPerGen {
		t.old = t.live
		t.live = make(map[uint64]Request, t.maxPerGen)
	}
	t.live[sockID] = r
}

// Take returns the most recent request on sockID, or ok=false if none is tracked. It is
// non-destructive: the entry remains so a split or repeated reply still correlates until the
// next Remember overwrites it.
func (t *Tracker) Take(sockID uint64) (Request, bool) {
	if r, ok := t.live[sockID]; ok {
		return r, true
	}
	if r, ok := t.old[sockID]; ok {
		return r, true
	}
	return Request{}, false
}

// Len reports the number of tracked sockets across both generations (bounded by ~2×maxPerGen).
func (t *Tracker) Len() int { return len(t.live) + len(t.old) }
