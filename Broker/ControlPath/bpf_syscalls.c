#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
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

int create_map(void) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));

    attr.map_type = BPF_MAP_TYPE_HASH;
    attr.key_size = sizeof(char);
    attr.value_size = sizeof(char[50]);
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

        BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),
        BPF_MOV64_IMM(BPF_REG_1, 1),
        BPF_RAW_INSN(BPF_STX | BPF_XADD | BPF_DW, BPF_REG_0, BPF_REG_1, 0, 0),

        BPF_MOV64_IMM(BPF_REG_0, 2),
        BPF_EXIT_INSN(),
    };
    size_t insn_cnt = sizeof(prog) / sizeof(prog[0]);

    union bpf_attr attr;
    char log_buf[4096] = {0};
    memset(&attr, 0, sizeof(attr));

    attr.prog_type = BPF_PROG_TYPE_XDP;
    attr.insns = (uint64_t)prog;
    attr.insn_cnt = insn_cnt;
    attr.license = (uint64_t)"GPL";
    attr.log_buf = (uint64_t)log_buf;
    attr.log_size = sizeof(log_buf);
    attr.log_level = 1;

    int prog_fd = sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    if (prog_fd < 0) {
        fprintf(stderr, "BPF_PROG_LOAD failed: %s\n", log_buf);
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

int add_key_if_not_exists(int map_fd, char key, char* value) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));

    attr.map_fd = map_fd;
    attr.key = &key;
    attr.value = value;
    attr.flags = BPF_NOEXIST;

    int ret = sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
    if (ret < 0) {
        if (errno == EEXIST) {
            printf("Key %u already exists in the map.\n", key);
            return 0;
        } else {
            perror("BPF_MAP_UPDATE_ELEM failed");
            return -1;
        }
    }

    printf("Key %u added to the map with value %s.\n", key, value);
    return 1;
}

int update_key(int map_fd, char key, char* value) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));

    attr.map_fd = map_fd;
    attr.key = &key;
    attr.value = &value;
    attr.flags = BPF_EXIST;

    int ret = sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
    if (ret < 0) {
        perror("BPF_MAP_UPDATE_ELEM failed");
        return -1;
    }

    printf("Key %u updated in the map with value %s.\n", key, value);
    return 0;
}
