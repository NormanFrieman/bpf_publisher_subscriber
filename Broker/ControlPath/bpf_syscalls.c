#include "bpf_syscalls.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/syscall.h>
#include <net/if.h>

static inline int sys_bpf(int cmd, union bpf_attr *attr, unsigned int size) {
    return syscall(__NR_bpf, cmd, attr, size);
}

// ---------------------------------------------------------------------

struct load_result load_prog(const char *obj_path) {
    struct load_result res = { -1, -1, NULL };

    struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object: %s\n", obj_path);
        return res;
    }

    if (bpf_object__load(obj) != 0) {
        fprintf(stderr, "Failed to load BPF object: %s\n", obj_path);
        bpf_object__close(obj);
        return res;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_udp_prog");
    if (!prog) {
        fprintf(stderr, "Failed to find program xdp_udp_prog in %s\n", obj_path);
        bpf_object__close(obj);
        return res;
    }

    struct bpf_map *map = bpf_object__find_map_by_name(obj, "broker_map");
    if (!map) {
        fprintf(stderr, "Failed to find map broker_map in %s\n", obj_path);
        bpf_object__close(obj);
        return res;
    }

    res.prog_fd = bpf_program__fd(prog);
    res.map_fd = bpf_map__fd(map);
    res.obj = obj;

    if (res.prog_fd < 0 || res.map_fd < 0) {
        fprintf(stderr, "Failed to get program or map fd from %s\n", obj_path);
        bpf_object__close(obj);
        res.prog_fd = -1;
        res.map_fd = -1;
        res.obj = NULL;
        return res;
    }

    printf("eBPF program loaded successfully with fd: %d\n", res.prog_fd);
    printf("eBPF map broker_map fd: %d\n", res.map_fd);
    return res;
}

int attach_xdp_link(int prog_fd, int ifindex) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));

    attr.link_create.prog_fd = prog_fd;
    attr.link_create.target_ifindex = ifindex;
    attr.link_create.attach_type = BPF_XDP;

    int link_fd = sys_bpf(BPF_LINK_CREATE, &attr, sizeof(attr));
    if (link_fd < 0) {
        perror("BPF_LINK_CREATE failed");
        return -1;
    }

    printf("eBPF program attached to interface index %d with link fd: %d\n", ifindex, link_fd);
    return link_fd;
}

int add_key_if_not_exists(int map_fd, char key) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));

    uint32_t key_u32 = (uint32_t)(unsigned char)key;

    struct map_value value;
    memset(&value, 0, sizeof(value));

    attr.map_fd = map_fd;
    attr.key = (uint64_t)(unsigned long)&key_u32;
    attr.value = (uint64_t)(unsigned long)&value;
    attr.flags = BPF_NOEXIST;

    int ret = sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
    if (ret < 0) {
        if (errno == EEXIST) {
            printf("Key %u already exists in the map.\n", key_u32);
            return 0;
        } else {
            perror("BPF_MAP_UPDATE_ELEM failed");
            return -1;
        }
    }

    printf("Key %u added to the map (empty value)\n", key_u32);
    return 1;
}

int update_key(int map_fd, uint32_t key, char* ip_str, char* port_str) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));

    char* endptr;
    errno = 0;
    long port_long = strtol(port_str, &endptr, 10);

    if (endptr == port_str || *endptr != '\0') {
        fprintf(stderr, "porta invalida (nao numerica): %s\n", port_str);
        return -1;
    }
    if (errno == ERANGE || port_long < 0 || port_long > 65535) {
        fprintf(stderr, "porta fora do intervalo valido (0-65535): %s\n", port_str);
        return -1;
    }
    uint16_t port = (uint16_t)port_long;

    struct map_value mv;
    memset(&mv, 0, sizeof(mv));

    if (inet_pton(AF_INET, ip_str, &mv.ip) != 1) {
        fprintf(stderr, "IP invalido: %s\n", ip_str);
        return -1;
    }
    mv.port = port;

    attr.map_fd = map_fd;
    attr.key = (uint64_t)(unsigned long)&key;
    attr.value = (uint64_t)(unsigned long)&mv;
    attr.flags = BPF_EXIST;

    int ret = sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
    if (ret < 0) {
        if (errno == ENOENT) {
            printf("Key %u does not exist, cannot update.\n", key);
            return 1;
        }
        perror("BPF_MAP_UPDATE_ELEM failed");
        return -1;
    }

    printf("Key %u updated with %s:%u\n", key, ip_str, port);
    return 0;
}
