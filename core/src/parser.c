#include "parser.h"
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <net/ethernet.h>

ParsedPacket parse_packet(const struct pcap_pkthdr *header, const u_char *packet, uint32_t packet_count, uint64_t total_bytes, const struct pcap_stat *stats, const struct timeval *start_time) {
    ParsedPacket parsed_packet;
    parsed_packet.packet_count = packet_count;
    parsed_packet.total_bytes = total_bytes;
    parsed_packet.start_time = *start_time;
    parsed_packet.packets_dropped = stats->ps_drop;
    parsed_packet.packets_received = stats->ps_recv;
    parsed_packet.packets_if_dropped = stats->ps_ifdrop; 
    parsed_packet.ts = header->ts;
    parsed_packet.packet_size = header->len;

    memset(parsed_packet.src_ip, 0, sizeof(parsed_packet.src_ip));
    memset(parsed_packet.dst_ip, 0, sizeof(parsed_packet.dst_ip));
    parsed_packet.protocol = 0;
    parsed_packet.src_port = 0;
    parsed_packet.dst_port = 0;
    parsed_packet.payload = NULL;
    parsed_packet.payload_length = 0;

    if (header->len < sizeof(struct ether_header)) {
        printf("Packet too short for Ethernet header\n");
        return parsed_packet;
    }

    struct ether_header *eth_header = (struct ether_header *) packet;

    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return parsed_packet;
    }

    if (header->len < sizeof(struct ether_header) + sizeof(struct ip)) {
        printf("Packet too short for IP header\n");
        return parsed_packet;
    }

    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    inet_ntop(AF_INET, &(ip_header->ip_src), parsed_packet.src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), parsed_packet.dst_ip, INET_ADDRSTRLEN);
    parsed_packet.protocol = ip_header->ip_p;

    struct tcphdr *tcp_header = NULL;
    struct udphdr *udp_header = NULL;

    if (parsed_packet.protocol == IPPROTO_TCP) {
        if (header->len < sizeof(struct ether_header) + ip_header->ip_hl * 4 + sizeof(struct tcphdr)) {
            printf("Packet too short for TCP header\n");
            return parsed_packet;
        }
        tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header->ip_hl * 4);
        parsed_packet.src_port = ntohs(tcp_header->source);
        parsed_packet.dst_port = ntohs(tcp_header->dest);
    }
    else if (parsed_packet.protocol == IPPROTO_UDP) {
        if (header->len < sizeof(struct ether_header) + ip_header->ip_hl * 4 + sizeof(struct udphdr)) {
            printf("Packet too short for UDP header\n");
            return parsed_packet;
        }
        udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + ip_header->ip_hl * 4);
        parsed_packet.src_port = ntohs(udp_header->source);
        parsed_packet.dst_port = ntohs(udp_header->dest);
    }

    parsed_packet.payload = packet + sizeof(struct ether_header) + ip_header->ip_hl * 4 + 
                            (parsed_packet.protocol == IPPROTO_TCP ? tcp_header->th_off * 4 : sizeof(struct udphdr));
    if (header->len < (parsed_packet.payload - packet)) {
        printf("Packet too short for payload\n");
        parsed_packet.payload_length = 0;
    } else {
        parsed_packet.payload_length = header->len - (parsed_packet.payload - packet);
    }

    return parsed_packet;
}

bool is_ip_packet(const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *)packet;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        return true;
    } else {
        return false;
    }
}
