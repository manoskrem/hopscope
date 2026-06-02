//go:build ignore

// SPDX-License-Identifier: GPL-2.0
//
// (The go:build constraint above keeps the Go toolchain from treating this as a cgo C
// source — it is compiled only by clang via bpf2go, never by `go build`.)
//
// Redis capture (Phase-5 no-code agent) — both directions.
//
// SEND path: an fentry hook on tcp_sendmsg fires for EVERY TCP send on the host kernel —
// regardless of which container or namespace issued it — so the agent observes a target's
// Redis commands with no change to the target. We keep only sends to the Redis port, copy a
// bounded PREFIX of the request bytes plus the issuing process (comm/pid) into a ring buffer,
// and let user space parse the RESP command + first key. The value (arg2+) is never parsed
// there, so it never leaves the host.
//
// RECV path (errors only): an fentry+fexit PAIR on tcp_recvmsg captures RESP simple-error
// replies ("-ERR …", "-WRONGTYPE …"). At ENTRY the destination buffer's iterator is pristine
// (offset 0), so we stash its base keyed by pid_tgid; the EXIT (after the kernel filled the
// buffer) reads ONLY the first framing byte and emits an event ONLY when it is '-'. Successful
// reply VALUES are therefore never copied off the recv buffer — that is the privacy gate. We
// do NOT use the fexit return value: a bounded prefix is copied and user space truncates the
// error line at the first CRLF. (Why the pair, not single-fexit: at fexit the iterator has been
// consumed by the copy; on ITER_IOVEC kernels the segment array rebases, so reading the base
// at exit can miss the start. Capturing the pristine base at entry is robust across UBUF/IOVEC.)
//
// fentry/fexit (over kprobe) give typed args straight from BTF, so there is no pt_regs /
// __TARGET_ARCH dependency and ONE bytecode loads on every little-endian arch (amd64 runner +
// arm64 dev kernels alike). We bind only (sk, msg) on tcp_recvmsg — a valid prefix of its args
// on every kernel; the trailing len/flags/addr_len differ across versions and we don't need them.

#include "vmlinux_min.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define DATA_LEN   256
#define REDIS_PORT 6379

// iter_type enum values on kernels >= 6.x: ITER_UBUF = 0, ITER_IOVEC = 1.
#define ITER_UBUF  0
#define ITER_IOVEC 1

// direction tags carried on every event (a single ring-buffer, one shape to the aggregator).
#define DIR_SEND       0
#define DIR_RECV_ERROR 1

// bpf_map_update_elem flag (UAPI constant, not in the minimal vmlinux header): no condition.
#define BPF_ANY 0

// Shared event — laid out identically to the bpf2go-generated Go struct (bpfRedisEvent).
// sock_id leads so its natural 8-byte alignment leaves no padding hole before it; direction +
// pad pack the byte after dport so the Go mirror has no implicit gap.
struct redis_event {
	__u64 sock_id;   // opaque (u64)sk — ephemeral per-socket correlation key (never serialized)
	__u32 pid;
	__u16 dport;
	__u8  direction; // DIR_SEND | DIR_RECV_ERROR
	__u8  pad;
	__u32 len;
	char  comm[16];
	__u8  data[DATA_LEN];
};

// Force struct redis_event into the program BTF so `bpf2go -type redis_event` emits it.
const struct redis_event *unused_redis_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); // 1 MiB
} events SEC(".maps");

// In-flight recv context: the pristine user buffer base captured at tcp_recvmsg ENTRY (before
// the copy consumes the iterator), keyed by pid_tgid, read+deleted at EXIT. LRU so a recv that
// never returns through our fexit cannot wedge the map.
struct recv_ctx {
	__u64 base;
	__u64 sock_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 10240);
	__type(key, __u64);
	__type(value, struct recv_ctx);
} inflight SEC(".maps");

// sk_dport returns the connected destination port (host order). For a Redis CLIENT socket this
// is 6379 on BOTH send and recv, so the same filter selects the client's request AND its reply;
// the server's accepted socket has the client's ephemeral port and is ignored.
static __always_inline __u16 sk_dport(struct sock *sk)
{
	return bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
}

// resolve_iov_base returns the start of the user data buffer for msg->msg_iter. At a hook ENTRY
// the iterator is pristine (offset 0), so this is the true start for both the about-to-be-sent
// and about-to-be-filled buffers.
//
// The iov_iter union changed across kernels:
//   * ITER_UBUF (single buffer, modern fast path) → __ubuf_iovec.iov_base
//   * ITER_IOVEC (segment array)                  → __iov[0].iov_base (legacy: iov[0])
// CO-RE field-existence guards keep reads of absent fields unreachable (and thus not relocated)
// on kernels that lack them. This is the iteration point if a future runner kernel changes the
// layout again.
static __always_inline void *resolve_iov_base(struct msghdr *msg)
{
	void *base = 0;
	__u8 itype = BPF_CORE_READ(msg, msg_iter.iter_type);

	if (itype == ITER_UBUF && bpf_core_field_exists(((struct iov_iter *)0)->__ubuf_iovec)) {
		base = BPF_CORE_READ(msg, msg_iter.__ubuf_iovec.iov_base);
	} else {
		const struct iovec *iov = 0;
		if (bpf_core_field_exists(((struct iov_iter *)0)->__iov))
			iov = BPF_CORE_READ(msg, msg_iter.__iov);
		else
			iov = BPF_CORE_READ(msg, msg_iter.iov);
		base = BPF_CORE_READ(iov, iov_base);
	}
	return base;
}

SEC("fentry/tcp_sendmsg")
int BPF_PROG(redis_tcp_sendmsg, struct sock *sk, struct msghdr *msg)
{
	__u16 dport = sk_dport(sk);
	if (dport != REDIS_PORT)
		return 0;

	__u64 total = BPF_CORE_READ(msg, msg_iter.count);
	if (total == 0)
		return 0;

	void *base = resolve_iov_base(msg);
	if (!base)
		return 0;

	struct redis_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->sock_id   = (__u64)(unsigned long)sk;
	e->pid       = bpf_get_current_pid_tgid() >> 32;
	e->dport     = dport;
	e->direction = DIR_SEND;
	e->pad       = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	// Copy a bounded prefix. Cap at DATA_LEN-1 and mask so the verifier sees a value strictly
	// within the buffer (256 & 255 == 0 would read nothing — hence -1).
	__u32 n = total < DATA_LEN ? (__u32)total : (DATA_LEN - 1);
	n &= (DATA_LEN - 1);
	if (bpf_probe_read_user(&e->data, n, base) != 0) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}
	e->len = n;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

// tcp_recvmsg ENTRY: stash the pristine destination buffer base before the copy consumes the
// iterator. Keyed by pid_tgid (the same task returns through the fexit below).
SEC("fentry/tcp_recvmsg")
int BPF_PROG(redis_tcp_recvmsg_entry, struct sock *sk, struct msghdr *msg)
{
	if (sk_dport(sk) != REDIS_PORT)
		return 0;

	void *base = resolve_iov_base(msg);
	if (!base)
		return 0;

	// NB: the local must NOT be named `ctx` — the BPF_PROG macro already binds `ctx` to the raw
	// (unsigned long long *) program context.
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct recv_ctx rc = {};
	rc.base    = (__u64)(unsigned long)base;
	rc.sock_id = (__u64)(unsigned long)sk;
	bpf_map_update_elem(&inflight, &pid_tgid, &rc, BPF_ANY);
	return 0;
}

// tcp_recvmsg EXIT: the buffer is now filled. Read ONLY the first framing byte; emit an event
// ONLY when it is '-' (a RESP simple error) — successful reply VALUES are never copied.
SEC("fexit/tcp_recvmsg")
int BPF_PROG(redis_tcp_recvmsg_exit, struct sock *sk, struct msghdr *msg)
{
	// NB: not named `ctx` — BPF_PROG owns that name for the raw program context.
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct recv_ctx *rc = bpf_map_lookup_elem(&inflight, &pid_tgid);
	if (!rc)
		return 0;

	__u64 base    = rc->base;
	__u64 sock_id = rc->sock_id;
	bpf_map_delete_elem(&inflight, &pid_tgid);
	if (!base)
		return 0;

	// The privacy gate: classify the reply from its single RESP type byte and bail on anything
	// that is not a simple error. A success reply's value bytes are never read past byte 0.
	__u8 first = 0;
	if (bpf_probe_read_user(&first, 1, (void *)(unsigned long)base) != 0)
		return 0;
	if (first != '-')
		return 0;

	struct redis_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->sock_id   = sock_id;
	e->pid       = pid_tgid >> 32;
	e->dport     = REDIS_PORT;
	e->direction = DIR_RECV_ERROR;
	e->pad       = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	// Copy a bounded prefix of the error line; user space truncates at the first CRLF.
	__u32 n = DATA_LEN - 1;
	n &= (DATA_LEN - 1);
	if (bpf_probe_read_user(&e->data, n, (void *)(unsigned long)base) != 0) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}
	e->len = n;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
