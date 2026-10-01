// Metadata header layout (must match kernel netfilter serialization)
struct ebpf_metadata {
    unsigned char version;          // offset 0
    unsigned char family;           // offset 1 (4=IPv4, 6=IPv6, 0=unknown)
    unsigned short dst_port;        // offset 2 (big-endian)
    unsigned short src_port;        // offset 4 (big-endian)
    unsigned char dst_addr[16];     // offset 6
    unsigned char src_addr[16];     // offset 22
} __attribute__((packed));

// Metadata header followed by packet payload.
struct ebpf_packet {
    struct ebpf_metadata meta;
    unsigned char payload[];
} __attribute__((packed));

__attribute__((section("prog"), used))
int ebpf_check_payload_a(void *ctx) {
    const struct ebpf_packet *packet = (const struct ebpf_packet *)ctx;
    if (!packet) return 0;

    if (packet->payload[0] == 'a') {
        return 1;
    }
    return 0;
}
