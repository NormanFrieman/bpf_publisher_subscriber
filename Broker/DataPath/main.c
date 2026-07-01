#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

struct map_value {
    __u32 ip;
    __u16 port;
    __u8  padding[2];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u8);
    __type(value, struct map_value);
    __uint(max_entries, 1024);
} map SEC(".maps");

SEC("xdp")
int xdp_udp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end){
        return XDP_PASS;
    }

    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end){
        return XDP_PASS;
    }

    if (iph->protocol != IPPROTO_UDP) {
        return XDP_PASS;
    }

    struct udphdr *udph = (void *)(iph + 1);
    if ((void *)(udph + 1) > data_end) {
        return XDP_PASS;
    }

    unsigned char *payload = (unsigned char *)(udph + 1);
    if (payload + 1 > (unsigned char *)data_end) {
        return XDP_PASS;
    }

    char key = payload[0];

    struct map_value *value = bpf_map_lookup_elem(&map, &key);
    if (value) {
        __u8 *ip_bytes = (__u8 *)&value->ip;
        bpf_printk("Match key=0x%x ip=%u.%u.%u.%u\n", key, ip_bytes[0], ip_bytes[1], ip_bytes[2]);
        bpf_printk("ip_last=%u port=%u\n", ip_bytes[3], value->port);
    } else {
        bpf_printk("No match for key=0x%x\n", key);
    }

    // __be32 dest_ip = iph->daddr;
    // __be32 src_ip = iph->saddr;
    // __u16 dest_port = __constant_ntohs(udph->dest);
    // __u16 src_port = __constant_ntohs(udph->source);

    // bpf_printk("UDP packet received: src_ip=%u, dest_ip=%u, src_port=%u, dest_port=%u\n", src_ip, dest_ip, src_port, dest_port);
    
    // __u8 *dest_bytes = (__u8 *)&dest_ip;
    // bpf_printk("UDP dest_port=%u dest_ip=%u.%u.%u.%u\n", dest_port, dest_bytes[0], dest_bytes[1], dest_bytes[2], dest_bytes[3]);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";