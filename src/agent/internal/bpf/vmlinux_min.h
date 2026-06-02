/* Guard name is __VMLINUX_H__ by convention (a real generated vmlinux.h uses the same),
 * which keeps libbpf's headers on their "vmlinux is present" path. */
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

/*
 * Minimal CO-RE type/struct subset for the Redis send-path capture.
 *
 * We deliberately do NOT vendor a multi-megabyte vmlinux.h. Only the handful of
 * fields the kprobe reads are declared, and `preserve_access_index` lets libbpf
 * relocate their REAL offsets from the running kernel's BTF at load time — so the
 * field offsets/layout declared here are irrelevant; only the field NAMES must
 * match the kernel's. (We even declare __ubuf_iovec / __iov / iov as flat siblings
 * though the kernel keeps them in a union — each name relocates independently.)
 *
 * The iov_iter union is the kernel-version-fragile part; see redis.bpf.c.
 */

/* Kernel integer types that libbpf's generated bpf_helper_defs.h references. A full
 * vmlinux.h would supply these; we declare the standard set so the helper prototypes parse. */
typedef signed char            __s8;
typedef unsigned char          __u8;
typedef short int              __s16;
typedef short unsigned int     __u16;
typedef int                    __s32;
typedef unsigned int           __u32;
typedef long long int          __s64;
typedef long long unsigned int __u64;
typedef __u16                  __le16;
typedef __u16                  __be16;
typedef __u32                  __le32;
typedef __u32                  __be32;
typedef __u64                  __le64;
typedef __u64                  __be64;
typedef __u16                  __sum16;
typedef __u32                  __wsum;
typedef long unsigned int      size_t;

/* Only the map-type ordinals we use (full enum lives in the UAPI / vmlinux.h). */
enum bpf_map_type {
	BPF_MAP_TYPE_LRU_HASH = 9,  /* per-pid_tgid in-flight recv context (auto-evicts on pressure) */
	BPF_MAP_TYPE_RINGBUF  = 27,
};

#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)

struct sock_common {
	__be16 skc_dport; /* destination port, network byte order */
	__u16  skc_num;
};

struct sock {
	struct sock_common __sk_common;
};

struct iovec {
	void  *iov_base;
	size_t iov_len;
};

struct iov_iter {
	__u8   iter_type;          /* ITER_UBUF / ITER_IOVEC / ... */
	size_t count;             /* bytes remaining (single-segment ⇒ the send length) */
	struct iovec __ubuf_iovec; /* ITER_UBUF single buffer (kernels >= 6.4)           */
	const struct iovec *__iov; /* ITER_IOVEC array, current field name (>= 6.4)      */
	const struct iovec *iov;   /* ITER_IOVEC array, legacy field name (< 6.4)        */
};

struct msghdr {
	struct iov_iter msg_iter;
};

#pragma clang attribute pop

#endif /* __VMLINUX_H__ */
