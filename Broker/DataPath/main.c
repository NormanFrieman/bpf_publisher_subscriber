#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct map_value {
    __u32 ip;
    __u16 port;
    __u8  mac[6];
};

struct broker_config {
    __u32 ifindex;
    __u8 mac[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u8);
    __type(value, struct map_value);
    __uint(max_entries, 1024);
} broker_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct broker_config);
    __uint(max_entries, 1);
} broker_config SEC(".maps");

static __always_inline __u16 csum_fold(__u32 csum) {
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return (__u16)~csum;
}

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

    if (iph->ihl < 5 || iph->protocol != IPPROTO_UDP) {
        return XDP_PASS;
    }

    struct udphdr *udph = (void *)iph + (iph->ihl * 4);
    if ((void *)(udph + 1) > data_end) {
        return XDP_PASS;
    }

    unsigned char *payload = (unsigned char *)(udph + 1);
    if (payload + 2 > (unsigned char *)data_end) {
        return XDP_PASS;
    }

    char command = payload[0];
    if (command != '2') {
        return XDP_PASS;
    }

    char key = payload[1];

    struct map_value *value = bpf_map_lookup_elem(&broker_map, &key);
    if (!value || value->ip == 0 || value->port == 0) {
        bpf_printk("No match or empty value for key=0x%x\n", key);
        return XDP_PASS;
    }

    __be32 old_daddr = iph->daddr;
    __be32 new_daddr = value->ip;
    __be16 new_dest = bpf_htons(value->port);
    __u32 daddr_host = bpf_ntohl(new_daddr);
    __u8 is_local = (daddr_host & 0xff000000) == 0x7f000000;

    if (udph->dest == new_dest) {
        return XDP_PASS;
    }

    struct broker_config *cfg = 0;
    if (!is_local) {
        __u32 cfg_key = 0;
        cfg = bpf_map_lookup_elem(&broker_config, &cfg_key);
        if (!cfg) {
            bpf_printk("No broker config found\n");
            return XDP_PASS;
        }
    }

    bpf_printk("Redirect key=0x%x to %u.%u.%u.%u:%u\n",
               key,
               (value->ip) & 0xff, (value->ip >> 8) & 0xff,
               (value->ip >> 16) & 0xff, (value->ip >> 24) & 0xff,
               value->port);

    udph->dest = new_dest;

    if (!is_local) {
        iph->daddr = new_daddr;
        __builtin_memcpy(eth->h_dest, value->mac, ETH_ALEN);
        __builtin_memcpy(eth->h_source, cfg->mac, ETH_ALEN);

        __u32 ip_csum = ~((__u32)iph->check) & 0xffff;
        ip_csum = bpf_csum_diff(&old_daddr, sizeof(old_daddr),
                                &new_daddr, sizeof(new_daddr), ip_csum);
        iph->check = csum_fold(ip_csum);
    }

    if (udph->check != 0) {
        udph->check = 0;
    }

    if (is_local) {
        return XDP_PASS;
    }

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
