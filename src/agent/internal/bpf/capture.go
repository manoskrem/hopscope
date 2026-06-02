//go:build linux

package bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// ErrNoKernelBTF means the running kernel exposes no BTF, so the CO-RE/fentry program cannot
// load. It is actionable: callers should fall back to a broker provider or OTLP (both kernel-free)
// or run on a BTF-enabled kernel. Checked via errors.Is by the entrypoint.
var ErrNoKernelBTF = errors.New("kernel BTF unavailable (no /sys/kernel/btf/vmlinux)")

// Direction tags a captured Event: a request send vs. a RESP error reply on the receive path.
const (
	DirSend      uint8 = 0
	DirRecvError uint8 = 1
)

// Event is one captured Redis observation: the issuing process and the bounded byte prefix
// (a request on the send path, or an error reply line on the recv path). SockID is an opaque,
// ephemeral per-socket key used only to correlate a reply back to its request — it is never
// serialized. Data is a private copy (the ring-buffer sample is reused after Read).
type Event struct {
	PID       uint32
	SockID    uint64
	Direction uint8
	Comm      string
	Data      []byte
}

// Capture loads the eBPF program, attaches the tcp_sendmsg fentry hook plus the tcp_recvmsg
// fentry+fexit pair, and streams decoded Events. It requires CAP_BPF/CAP_PERFMON (or privileged)
// and kernel BTF.
type Capture struct {
	objs   bpfObjects
	links  []link.Link
	reader *ringbuf.Reader
}

// NewCapture loads + attaches. The caller must Close the returned Capture.
func NewCapture() (*Capture, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}

	// Preflight: CO-RE relocations AND the fentry attach both require the running kernel's BTF.
	// Probe it up front so a BTF-less kernel (some WSL2 builds, older/locked-down distros) yields
	// an actionable error instead of a raw relocation/verifier failure deeper in the load.
	if _, err := btf.LoadKernelSpec(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoKernelBTF, err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects (need kernel BTF at /sys/kernel/btf): %w", err)
	}

	// Attach all three programs: the send-path fentry and the recv-path fentry+fexit pair.
	// The pair must both attach (the fexit reads what the fentry stashed), so any failure tears
	// down what is already attached.
	attachments := []struct {
		desc string
		prog *ebpf.Program
		at   ebpf.AttachType
	}{
		{"fentry tcp_sendmsg", objs.RedisTcpSendmsg, ebpf.AttachTraceFEntry},
		{"fentry tcp_recvmsg", objs.RedisTcpRecvmsgEntry, ebpf.AttachTraceFEntry},
		{"fexit tcp_recvmsg", objs.RedisTcpRecvmsgExit, ebpf.AttachTraceFExit},
	}
	var links []link.Link
	for _, a := range attachments {
		lk, err := link.AttachTracing(link.TracingOptions{Program: a.prog, AttachType: a.at})
		if err != nil {
			for _, l := range links {
				l.Close()
			}
			objs.Close()
			return nil, fmt.Errorf("attach %s: %w", a.desc, err)
		}
		links = append(links, lk)
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		for _, l := range links {
			l.Close()
		}
		objs.Close()
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}

	return &Capture{objs: objs, links: links, reader: rd}, nil
}

// Run reads events until ctx is cancelled, invoking handle for each decoded Event.
// handle must not block (it should hand off to a buffered sink).
func (c *Capture) Run(ctx context.Context, handle func(Event)) error {
	go func() {
		<-ctx.Done()
		c.reader.Close() // unblocks the Read below
	}()

	for {
		rec, err := c.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				return ctx.Err()
			}
			continue // transient read error — keep going
		}
		if ev, ok := decode(rec.RawSample); ok {
			handle(ev)
		}
	}
}

// Close detaches the probes and releases the program/maps.
func (c *Capture) Close() error {
	c.reader.Close()
	for _, l := range c.links {
		l.Close()
	}
	return c.objs.Close()
}

// decode turns a raw ring-buffer sample into an Event, copying out only the captured
// prefix (Len bytes) and the NUL-trimmed comm.
func decode(raw []byte) (Event, bool) {
	var re bpfRedisEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &re); err != nil {
		return Event{}, false
	}
	n := int(re.Len)
	if n < 0 || n > len(re.Data) {
		n = len(re.Data)
	}
	return Event{
		PID:       re.Pid,
		SockID:    re.SockId,
		Direction: re.Direction,
		Comm:      commString(re.Comm),
		Data:      append([]byte(nil), re.Data[:n]...),
	}, true
}

// commString converts a fixed-width, NUL-padded kernel comm into a Go string.
func commString(b [16]int8) string {
	buf := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		buf = append(buf, byte(c))
	}
	return string(buf)
}
