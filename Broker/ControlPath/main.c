#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include "bpf_syscalls.h"

#define PORT 10000
#define BUFFER_SIZE 1024

void setup_commands(char* buffer, int* map_fd) {
    switch (buffer[0]) {
        case '0':
            printf("Command 0 received: eBPF map publisher\n");
            char key = buffer[1];
            char value[sizeof(buffer - 2)];

            strcpy(value, buffer + 2);
            printf("%s\n", value);

            add_key_if_not_exists(*map_fd, key, value);
            break;
        case '1':
            printf("Command 1 received: eBPF map subscribe\n");
            // update_key(*map_fd, 1, 200);
            break;
        case '2':
            printf("Command 2 received: message publishing\n");
            break;
        default:
            printf("Unknown command received: %c\n", buffer[0]);
            break;
    }
}

void config_udp(int* sockfd, struct sockaddr_in* server_addr) {
    *sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (*sockfd < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(server_addr, 0, sizeof(*server_addr));
    server_addr->sin_family = AF_INET;
    server_addr->sin_addr.s_addr = INADDR_ANY;
    server_addr->sin_port = htons(PORT);

    if (bind(*sockfd, (struct sockaddr *)server_addr, sizeof(*server_addr)) < 0) {
        perror("bind failed");
        close(*sockfd);
        exit(EXIT_FAILURE);
    }
}

void listen_udp(char* buffer, int* sockfd, int* map_fd, struct sockaddr_in* client_addr, socklen_t client_len) {
    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        ssize_t n = recvfrom(*sockfd, buffer, BUFFER_SIZE - 1, 0, (struct sockaddr *)client_addr, &client_len);

        if (n < 0) {
            perror("recvfrom failed");
            continue;
        }

        printf("Received message: %s\n", buffer);
        printf("From client: %s:%d\n", inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port));

        setup_commands(buffer, map_fd);
    }

    close(*sockfd);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <network_interface>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int map_fd = create_map();
    if (map_fd < 0) {
        fprintf(stderr, "Failed to create eBPF map\n");
        exit(EXIT_FAILURE);
    }
    
    int prog_fd = load_prog(map_fd);
    if (prog_fd < 0) {
        close(map_fd);
        fprintf(stderr, "Failed to load eBPF program\n");
        exit(EXIT_FAILURE);
    }

    int ifindex = if_nametoindex(argv[1]);
    if (ifindex == 0) {
        perror("if_nametoindex failed");
        close(prog_fd);
        close(map_fd);
        exit(EXIT_FAILURE);
    }

    int link_fd = attach_xdp_link(prog_fd, ifindex);
    if (link_fd < 0) {
        close(prog_fd);
        close(map_fd);
        fprintf(stderr, "Failed to attach eBPF program to interface\n");
        exit(EXIT_FAILURE);
    }

    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];

    config_udp(&sockfd, &server_addr);
    listen_udp(buffer, &sockfd, &map_fd, &client_addr, client_len);

    close(link_fd);
    close(prog_fd);
    close(map_fd);

    return 0;
}