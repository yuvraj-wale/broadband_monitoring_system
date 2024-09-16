#ifndef PARSER_H
#define PARSER_H

#include <pcap.h>
#include <stdbool.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

typedef struct {
    struct timeval ts;
    uint32_t packet_size;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    uint8_t protocol;
    uint16_t src_port;
    uint16_t dst_port;
    const u_char *payload;
    int payload_length;
    struct timeval start_time;
    uint32_t packet_count;
    uint64_t total_bytes;
    uint64_t packets_received;
    uint32_t packets_dropped;
    uint32_t packets_if_dropped;
} ParsedPacket;

ParsedPacket parse_packet(const struct pcap_pkthdr *header, const u_char *packet, uint32_t packet_count, uint64_t total_bytes, const struct pcap_stat *stats, const struct timeval *start_time);
bool is_ip_packet(const u_char *packet);

#endif
