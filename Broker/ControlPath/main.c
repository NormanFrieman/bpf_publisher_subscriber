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

static const char *g_ifname = NULL;

/*
    0 - Cria um novo map (publisher)
    1 - Atualiza um map existente (subscriber)
    2 - Publica uma mensagem (publisher)
*/

void create_new_map(char* buffer, int* map_fd, char key) {
    printf("\nCommand 0 received: eBPF map publisher\n");
    char value[sizeof(buffer - 2)];

    strcpy(value, buffer + 2);
    printf("%s\n", value);

    add_key_if_not_exists(*map_fd, key);
}

void update_existing_map(char* buffer, int* map_fd, char key, struct sockaddr_in* client_addr) {
    printf("\nCommand 1 received: eBPF map subscribe\n");

    char ip_str[32];
    char port_str[16];
    snprintf(ip_str, sizeof(ip_str), "%s", inet_ntoa(client_addr->sin_addr));
    snprintf(port_str, sizeof(port_str), "%d", ntohs(client_addr->sin_port));
    printf("Client IP: %s, Port: %s\n", ip_str, port_str);

    uint32_t key_u32 = (uint32_t)(unsigned char)key;
    uint32_t ip = client_addr->sin_addr.s_addr;

    uint8_t mac[6];
    if ((ntohl(ip) & 0xff000000) == 0x7f000000) {
        memset(mac, 0, sizeof(mac));
    } else {
        if (get_arp_mac(g_ifname, ip, mac) < 0) {
            fprintf(stderr, "Failed to resolve MAC for %s\n", ip_str);
            return;
        }
    }
    printf("Client MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    update_key(*map_fd, key_u32, ip_str, port_str, mac);
}

void setup_commands(char* buffer, int* map_fd, struct sockaddr_in* client_addr) {
    char command = buffer[0];
    char key = buffer[1];
    switch (command) {
        case '0':
            create_new_map(buffer, map_fd, key);
            break;
        case '1':
            update_existing_map(buffer, map_fd, key, client_addr);
            break;
        case '2':
            printf("\nCommand 2 received: message publishing\n");
            printf("If you see this message, it means the publisher failed.\n");
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

        setup_commands(buffer, map_fd, client_addr);
    }

    close(*sockfd);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <network_interface>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    g_ifname = argv[1];

    struct load_result lr = load_prog("../DataPath/main.o", argv[1]);
    if (lr.prog_fd < 0 || lr.map_fd < 0 || lr.cfg_fd < 0) {
        fprintf(stderr, "Failed to load eBPF program, map and config\n");
        exit(EXIT_FAILURE);
    }

    int map_fd = lr.map_fd;
    int prog_fd = lr.prog_fd;

    int ifindex = if_nametoindex(argv[1]);
    if (ifindex == 0) {
        perror("if_nametoindex failed");
        close(prog_fd);
        close(map_fd);
        bpf_object__close(lr.obj);
        exit(EXIT_FAILURE);
    }

    int link_fd = attach_xdp_link(prog_fd, ifindex);
    if (link_fd < 0) {
        close(prog_fd);
        close(map_fd);
        bpf_object__close(lr.obj);
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
    bpf_object__close(lr.obj);

    return 0;
}
