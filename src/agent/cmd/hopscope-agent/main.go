//go:build linux

// Command hopscope-agent is the no-code interception agent: it captures Redis
// traffic at the kernel via eBPF and streams normalized EventEnvelopes to the
// Hopscope engine's gRPC Ingestion service — with no change to the target app or
// broker. See src/agent/README.md.
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hopscope/agent/internal/bpf"
	"github.com/hopscope/agent/internal/correlate"
	"github.com/hopscope/agent/internal/mapper"
	"github.com/hopscope/agent/internal/resp"
	"github.com/hopscope/agent/internal/sink"
)

// recvTrackerSize bounds the per-socket request tracker. A reply correlates to the request that
// immediately preceded it on the same socket, so only briefly-in-flight sockets matter.
const recvTrackerSize = 4096

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	target := getenv("HOPSCOPE_AGENT_TARGET", "engine:4318")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	capt, err := bpf.NewCapture()
	if err != nil {
		if errors.Is(err, bpf.ErrNoKernelBTF) {
			log.Error("agent: this kernel has no BTF, so the eBPF capture cannot load. Use a broker "+
				"provider (RabbitMQ/Redis/Kafka) or OTLP instead — both are kernel-free and need no "+
				"agent — or run the agent on a BTF-enabled kernel (most modern Linux servers and "+
				"managed Kubernetes nodes qualify; check: ls /sys/kernel/btf/vmlinux). See README.",
				"err", err)
			os.Exit(2)
		}
		log.Error("agent: failed to start eBPF capture (needs privileged + kernel BTF)", "err", err)
		os.Exit(1)
	}
	defer capt.Close()

	snk := sink.New(sink.Config{Target: target, Logger: log})
	m := mapper.New()
	// tracker remembers the last request per socket so a later error reply on that socket can be
	// attributed to it. The capture callback runs on a single goroutine, so it needs no lock.
	tracker := correlate.New(recvTrackerSize)

	go func() {
		if err := snk.Run(ctx); err != nil && ctx.Err() == nil {
			log.Error("agent: sink stopped unexpectedly", "err", err)
		}
	}()

	log.Info("agent: capturing Redis traffic at the kernel", "engine", target)
	err = capt.Run(ctx, func(ev bpf.Event) {
		switch ev.Direction {
		case bpf.DirSend:
			verb, key, ok := resp.Parse(ev.Data)
			if !ok {
				return // not a parseable RESP command (or a non-command segment)
			}
			env := m.FromCommand(ev.Comm, verb, key, ev.PID, time.Now())
			tracker.Remember(ev.SockID, correlate.Request{
				Verb: verb, FirstKey: key, Comm: ev.Comm, PID: ev.PID,
				HopID: env.GetHopId(), TraceID: env.GetTraceId(),
			})
			snk.Enqueue(env) // never blocks (drop-oldest); a dropped hop never stalls capture

		case bpf.DirRecvError:
			code, line, ok := resp.ParseError(ev.Data)
			if !ok {
				return // not a RESP error reply
			}
			req, found := tracker.Take(ev.SockID)
			if !found {
				return // no request to attribute the error to (e.g. capture started mid-connection)
			}
			env := m.FromError(req.Comm, req.Verb, req.FirstKey, req.HopID, req.TraceID,
				code, line, req.PID, time.Now())
			snk.Enqueue(env)
		}
	})
	if err != nil && ctx.Err() == nil {
		log.Error("agent: capture stopped unexpectedly", "err", err)
	}

	if dropped := snk.Dropped(); dropped > 0 {
		log.Warn("agent: envelopes dropped under back-pressure", "count", dropped)
	}
	log.Info("agent: shutting down")
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
