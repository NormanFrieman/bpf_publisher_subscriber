#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

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

    __u16 dest_port = __constant_ntohs(udph->dest);
    __u16 src_port = __constant_ntohs(udph->source);

    bpf_printk("UDP packet received: src_port=%u, dest_port=%u\n", src_port, dest_port);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";