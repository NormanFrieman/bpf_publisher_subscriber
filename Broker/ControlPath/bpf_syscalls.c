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

#define BPF_ALU64_IMM(OP, DST, IMM) \
    ((struct bpf_insn){ .code = BPF_ALU64 | BPF_OP(OP) | BPF_K, \
        .dst_reg = DST, .src_reg = 0, .off = 0, .imm = IMM })

#define BPF_MOV64_IMM(DST, IMM) \
    ((struct bpf_insn){ .code = BPF_ALU64 | BPF_MOV | BPF_K, \
        .dst_reg = DST, .src_reg = 0, .off = 0, .imm = IMM })

#define BPF_MOV64_REG(DST, SRC) \
    ((struct bpf_insn){ .code = BPF_ALU64 | BPF_MOV | BPF_X, \
        .dst_reg = DST, .src_reg = SRC, .off = 0, .imm = 0 })

#define BPF_STX_MEM(SIZE, DST, SRC, OFF) \
    ((struct bpf_insn){ .code = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM, \
        .dst_reg = DST, .src_reg = SRC, .off = OFF, .imm = 0 })

#define BPF_JMP_IMM(OP, DST, IMM, OFF) \
    ((struct bpf_insn){ .code = BPF_JMP | BPF_OP(OP) | BPF_K, \
        .dst_reg = DST, .src_reg = 0, .off = OFF, .imm = IMM })

#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM) \
    ((struct bpf_insn){ .code = CODE, .dst_reg = DST, .src_reg = SRC, \
        .off = OFF, .imm = IMM })

#define BPF_EXIT_INSN() \
    ((struct bpf_insn){ .code = BPF_JMP | BPF_EXIT, \
        .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 })

#define BPF_EMIT_CALL(FUNC) \
    ((struct bpf_insn){ .code = BPF_JMP | BPF_CALL, \
        .dst_reg = 0, .src_reg = 0, .off = 0, .imm = FUNC })

#define BPF_LD_MAP_FD(DST, MAP_FD) \
    BPF_RAW_INSN(BPF_LD | BPF_DW | BPF_IMM, DST, BPF_PSEUDO_MAP_FD, 0, MAP_FD), \
    BPF_RAW_INSN(0, 0, 0, 0, 0)

// ---------------------------------------------------------------------

int create_map(void) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));

    attr.map_type = BPF_MAP_TYPE_HASH;
    attr.key_size = sizeof(char);
    attr.value_size = sizeof(struct map_value);
    attr.max_entries = 1024;

    strncpy(attr.map_name, "pkt_count_map", sizeof(attr.map_name) - 1);

    int map_fd = sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
    if (map_fd < 0) {
        perror("BPF_MAP_CREATE failed");
        return -1;
    }

    printf("eBPF map created successfully with fd: %d\n", map_fd);
    return map_fd;
}

int load_prog(int map_fd) {
    struct bpf_insn prog[] = {
        BPF_MOV64_IMM(BPF_REG_0, 1),
        BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4),

        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),

        BPF_LD_MAP_FD(BPF_REG_1, map_fd),

        BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),

        BPF_MOV64_IMM(BPF_REG_0, 2),
        BPF_EXIT_INSN(),
    };
    size_t insn_cnt = sizeof(prog) / sizeof(prog[0]);

    union bpf_attr attr;
    char log_buf[4096] = {0};
    memset(&attr, 0, sizeof(attr));

    attr.prog_type = BPF_PROG_TYPE_XDP;
    attr.insns = (uint64_t)(unsigned long)prog;
    attr.insn_cnt = insn_cnt;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_buf = (uint64_t)(unsigned long)log_buf;
    attr.log_size = sizeof(log_buf);
    attr.log_level = 1;

    int prog_fd = sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    if (prog_fd < 0) {
        fprintf(stderr, "BPF_PROG_LOAD failed: %s\n%s\n", strerror(errno), log_buf);
        return -1;
    }

    printf("eBPF program loaded successfully with fd: %d\n", prog_fd);
    return prog_fd;
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
