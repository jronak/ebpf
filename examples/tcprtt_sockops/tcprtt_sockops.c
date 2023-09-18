//go:build ignore

#include "common.h"

#include "bpf_endian.h"
#include "bpf_sockops.h"
#include "bpf_tracing.h"

#define AF_INET 2
#define AF_INET6 10
#define SOCKOPS_MAP_SIZE 65535

char __license[] SEC("license") = "Dual MIT/GPL";

enum {
	SOCK_TYPE_ACTIVE  = 0,
	SOCK_TYPE_PASSIVE = 1,
};

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__type(key, struct sk_key);
	__type(value, __u64);
	__uint(max_entries, SOCKOPS_MAP_SIZE);
} sock_map SEC(".maps");

struct sk_key {
	u32 local_port;
	u32 remote_port;
};

static inline void init_sk_key(struct bpf_sock_ops *skops, struct sk_key *sk_key) {
	// sk_key->local_ip4   = bpf_ntohl(skops->local_ip4);
	// sk_key->remote_ip4  = bpf_ntohl(skops->remote_ip4);
	sk_key->local_port  = skops->local_port;
	sk_key->remote_port = bpf_ntohl(skops->remote_port);
}

static inline void bpf_sock_ops_establish_cb(struct bpf_sock_ops *skops, u8 sock_type) {
	int err;
	struct sk_key sk_key = {};
	bpf_printk("inside establish op:%d ip:%d remote-port:%d local-port:%d family:%d\n", skops->op, skops->remote_ip4, bpf_ntohl(skops->remote_port), skops->local_port, skops->family);
	if (skops == NULL || !(skops->family == AF_INET || skops->family == AF_INET6)) {
		bpf_printk("returning from establish op: %d ip:%d family:%d\n", skops->op, skops->remote_ip4, skops->family);
		return;
	}

	init_sk_key(skops, &sk_key);
	err = bpf_sock_hash_update(skops, &sock_map, &sk_key, BPF_NOEXIST);
	if (err != 0) {
		bpf_printk("failed to update sockhash: op:%d ip:%d remote-port:%d local-port:%d family:%d\n", skops->op, skops->remote_ip4, bpf_ntohl(skops->remote_port), skops->local_port, skops->family);
		return;
	}
	bpf_printk("added this in the sockmap ip:%d\n", skops->remote_ip4);
}

#define __bpf_md_ptr(type, name) \
	union { \
		type name; \
		__u64 : 64; \
	} __attribute__((aligned(8)))

struct sk_msg_md {
	__bpf_md_ptr(void *, data);
	__bpf_md_ptr(void *, data_end);

	__u32 family;
	__u32 remote_ip4;    /* Stored in network byte order */
	__u32 local_ip4;     /* Stored in network byte order */
	__u32 remote_ip6[4]; /* Stored in network byte order */
	__u32 local_ip6[4];  /* Stored in network byte order */
	__u32 remote_port;   /* Stored in network byte order */
	__u32 local_port;    /* stored in host byte order */
	__u32 size;          /* Total size of sk_msg */

	__bpf_md_ptr(struct bpf_sock *, sk); /* current socket */
};

enum {
	BPF_F_INGRESS = (1ULL << 0),
};

static inline void init_sk_msg_key(struct sk_msg_md *msg, struct sk_key *sk_key) {
	// sk_key->local_ip4   = bpf_ntohl(msg->local_ip4);
	// sk_key->remote_ip4  = bpf_ntohl(msg->remote_ip4);
	sk_key->local_port  = bpf_ntohl(msg->remote_port);
	sk_key->remote_port = msg->local_port;
}

SEC("sk_msg")
int bpf_tcpip_bypass(struct sk_msg_md *msg) {
	struct sk_key key = {};
	init_sk_msg_key(msg, &key);
	long res = bpf_msg_redirect_hash(msg, &sock_map, &key, BPF_F_INGRESS);
	bpf_printk("got message res - remote-port:%d local-port:%d res:%ld\n", bpf_ntohl(msg->remote_port), msg->local_port, res);
	return 1;
}

SEC("sockops")
int bpf_sockops_cb(struct bpf_sock_ops *skops) {
	u32 op;
	op = skops->op;
	bpf_printk("sockops op: %d ip:%d\n", op, skops->remote_ip4);

	switch (op) {
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		bpf_sock_ops_establish_cb(skops, SOCK_TYPE_ACTIVE);
		break;
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		bpf_sock_ops_establish_cb(skops, SOCK_TYPE_PASSIVE);
		break;
	}

	return 0;
}
