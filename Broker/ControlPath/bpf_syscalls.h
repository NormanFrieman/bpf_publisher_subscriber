#ifndef BPF_SYSCALLS_H
#define BPF_SYSCALLS_H

#include <stdint.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>

#define MAP_VALUE_SIZE 8

struct map_value {
    uint32_t ip;
    uint16_t port;
    uint8_t  padding[2];
};

struct load_result {
    int prog_fd;
    int map_fd;
    struct bpf_object *obj;
};

struct load_result load_prog(const char *obj_path);

int attach_xdp_link(int prog_fd, int ifindex);

int add_key_if_not_exists(int map_fd, char key);

int update_key(int map_fd, uint32_t key, char* ip_str, char* port_str);

#endif // BPF_SYSCALLS_H
