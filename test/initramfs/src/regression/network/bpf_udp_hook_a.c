// SPDX-License-Identifier: MPL-2.0

// Loads a drop-all eBPF program, attaches it to the Asterinas UDP send
// netfilter hook, prints the resulting prog FD, link FD, and PID, then
// pauses forever to keep both FDs (and therefore the attachment) alive.
//
// Pair with bpf_udp_hook_b, which detaches by reaching into this process
// via pidfd_getfd(2) and closing the duplicated FD.

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SYS_bpf
#define SYS_bpf 321
#endif

#define BPF_PROG_LOAD 5
#define BPF_LINK_CREATE 28

#define BPF_PROG_TYPE_NETFILTER 45
#define BPF_ATTACH_TYPE_NETFILTER 45

// Asterinas-private hook number for the UDP send hook.
#define AST_HOOK_UDP_SEND 0x1000

struct bpf_prog_load_attr {
	uint32_t prog_type;
	uint32_t insn_cnt;
	uint64_t insns;
	uint64_t license;
	uint32_t log_level;
	uint32_t log_size;
	uint64_t log_buf;
	uint32_t kern_version;
	uint32_t prog_flags;
	char prog_name[16];
	uint32_t prog_ifindex;
	uint32_t expected_attach_type;
};

struct bpf_link_create_attr {
	uint32_t prog_fd;
	uint32_t target_fd_or_ifindex;
	uint32_t attach_type;
	uint32_t flags;
	uint32_t nf_pf;
	uint32_t nf_hooknum;
	int32_t nf_priority;
	uint32_t nf_flags;
};

// only accept the packet which starts with 'a'
static const uint8_t DROP_ALL_BYTECODE[] = {
	0x71, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ldxb r0, [r1 + 0]
	0x15, 0x00, 0x02, 0x00, 0x61, 0x00, 0x00, 0x00, // jeq r0, 'a', +2
	0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov64 r0, 0
	0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
	0xb7, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // mov64 r0, 1
	0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
};

static int bpf(int cmd, void *attr, unsigned int size)
{
	return syscall(SYS_bpf, cmd, attr, size);
}

int main(void)
{
	struct bpf_prog_load_attr load_attr = {
		.prog_type = BPF_PROG_TYPE_NETFILTER,
		.insn_cnt = sizeof(DROP_ALL_BYTECODE) / 8,
		.insns = (uint64_t)(uintptr_t)DROP_ALL_BYTECODE,
	};
	int prog_fd = bpf(BPF_PROG_LOAD, &load_attr, sizeof(load_attr));
	if (prog_fd < 0) {
		perror("BPF_PROG_LOAD");
		return 1;
	}

	struct bpf_link_create_attr link_attr = {
		.prog_fd = prog_fd,
		.attach_type = BPF_ATTACH_TYPE_NETFILTER,
		.nf_hooknum = AST_HOOK_UDP_SEND,
	};
	int link_fd = bpf(BPF_LINK_CREATE, &link_attr, sizeof(link_attr));
	if (link_fd < 0) {
		perror("BPF_LINK_CREATE");
		return 1;
	}

	printf("pid=%d prog_fd=%d link_fd=%d\n", (int)getpid(), prog_fd,
	       link_fd);
	fflush(stdout);

	// Keep the FDs alive so another process can target them.
	for (;;) {
		pause();
	}
}
