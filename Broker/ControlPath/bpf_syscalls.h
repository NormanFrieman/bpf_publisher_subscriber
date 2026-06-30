#ifndef BPF_SYSCALLS_H
#define BPF_SYSCALLS_H

#include <stdint.h>
#include <linux/bpf.h>

int create_map(void);

int load_prog(int map_fd);

int attach_xdp_link(int prog_fd, int ifindex);

int add_key_if_not_exists(int map_fd, char key, char* initial_value);

int update_key(int map_fd, char key, char* new_value);

#endif // BPF_SYSCALLS_H
