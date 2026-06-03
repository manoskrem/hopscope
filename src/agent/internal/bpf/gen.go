// Package bpf loads the Redis-RESP eBPF capture program and streams decoded events.
//
// The program has three hooks over one ring buffer: fentry/tcp_sendmsg (request capture) and a
// fentry+fexit pair on tcp_recvmsg (error-reply capture). Each event carries a direction tag so
// user space routes it (send → command, recv-error → Failed). See redis.bpf.c.
//
// The go:generate directive below compiles redis.bpf.c into a CO-RE object and emits the
// Go loader wrappers (bpf_bpfel.go / bpf_bpfeb.go) plus the bpfRedisEvent type (whose fields
// mirror struct redis_event, including sock_id + direction). `go generate ./...` runs it inside
// the Docker build, where clang + libbpf headers are available; the generated wrappers and .o
// files are gitignored (build artifacts, not source). On non-Linux dev machines this file is the
// only member of the package, so it still compiles.
//
// The program uses fentry/fexit (typed BTF args), so it needs no __TARGET_ARCH define and the
// single little-endian object loads on both amd64 (the nightly runner) and arm64 (dev) kernels.
package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type redis_event -cc clang -cflags "-O2 -g -Wall" bpf redis.bpf.c
