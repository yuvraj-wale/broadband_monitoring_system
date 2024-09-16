#include "classifier.h"
#include "parser.h"
#include "capture.h"
#include <maxminddb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

MMDB_s mmdb;

void initialize_geoip(const char *db_path) {
    int status = MMDB_open(db_path, MMDB_MODE_MMAP, &mmdb);
    if (status != MMDB_SUCCESS) {
        fprintf(stderr, "Error opening GeoIP database: %s\n", MMDB_strerror(status));
    }
}

void cleanup_geoip() {
    MMDB_close(&mmdb);
}

const char *classify_by_encryption(const ParsedPacket *packet) {
    static const uint16_t encrypted_ports[] = {
        443, 993, 995, 5222, 5223, 465, 636, 989, 990, 8443, 8883, 2083, 2087,
        5061, 194, 6697, 8888, 9443, 9951, 9901, 10443, 4433, 4434, 4435,
        853, 261, 448, 563, 614, 631, 614, 686, 695, 832, 898, 981, 992,
        1311, 7000, 7002, 8531, 8888, 9091
    };
    static const size_t num_encrypted_ports = sizeof(encrypted_ports) / sizeof(encrypted_ports[0]);

    for (size_t i = 0; i < num_encrypted_ports; ++i) {
        if (packet->dst_port == encrypted_ports[i] || packet->src_port == encrypted_ports[i]) {
            return "Encrypted";
        }
    }

    if (packet->payload_length >= 5) {
        const unsigned char *payload = (const unsigned char *)packet->payload;
        if (payload[0] == 0x16 && payload[1] == 0x03 && 
            (payload[2] >= 0x00 && payload[2] <= 0x03)) {
            return "Encrypted";
        }
    }

    return "Unencrypted";
}

const char *classify_by_protocol(const ParsedPacket *packet) {
    switch (packet->protocol) {
        case IPPROTO_TCP:
            return "TCP";
        case IPPROTO_UDP:
            return "UDP";
        case IPPROTO_ICMP:
            return "ICMP";
        case IPPROTO_IGMP:
            return "IGMP";
        case IPPROTO_SCTP:
            return "SCTP";
        case IPPROTO_GRE:
            return "GRE";
        case IPPROTO_ESP:
            return "ESP";
        case IPPROTO_AH:
            return "AH";
        default:
            return "Other";
    }
}

const char *classify_by_application_protocol(const ParsedPacket *packet) {
    #define CHECK_PORT(port, protocol) \
        if (packet->src_port == port || packet->dst_port == port) return protocol

    if (packet->protocol == IPPROTO_TCP) {
        CHECK_PORT(80, "HTTP");
        CHECK_PORT(443, "HTTPS");
        CHECK_PORT(21, "FTP");
        CHECK_PORT(22, "SSH");
        CHECK_PORT(23, "Telnet");
        CHECK_PORT(25, "SMTP");
        CHECK_PORT(110, "POP3");
        CHECK_PORT(143, "IMAP");
        CHECK_PORT(993, "IMAPS");
        CHECK_PORT(995, "POP3S");
        CHECK_PORT(3306, "MySQL");
        CHECK_PORT(5432, "PostgreSQL");
        CHECK_PORT(3389, "RDP");
        CHECK_PORT(1723, "PPTP");
        CHECK_PORT(5900, "VNC");
        CHECK_PORT(5222, "XMPP Client");
        CHECK_PORT(5223, "XMPP Client over SSL");
        CHECK_PORT(5060, "SIP");
        CHECK_PORT(8080, "HTTP Alternate");
        CHECK_PORT(8443, "HTTPS Alternate");
        CHECK_PORT(6697, "IRC over SSL");
        CHECK_PORT(6667, "IRC");
        CHECK_PORT(27017, "MongoDB");
        CHECK_PORT(1433, "MS SQL");
        CHECK_PORT(3128, "Squid Proxy");
        CHECK_PORT(5601, "Kibana");
        CHECK_PORT(9200, "Elasticsearch");
        CHECK_PORT(9300, "Elasticsearch Cluster");
        CHECK_PORT(6379, "Redis");
        CHECK_PORT(11211, "Memcached");
        CHECK_PORT(5672, "AMQP");
        CHECK_PORT(15672, "RabbitMQ Management");
    }
    else if (packet->protocol == IPPROTO_UDP) {
        CHECK_PORT(53, "DNS");
        CHECK_PORT(67, "DHCP Server");
        CHECK_PORT(68, "DHCP Client");
        CHECK_PORT(69, "TFTP");
        CHECK_PORT(123, "NTP");
        CHECK_PORT(161, "SNMP");
        CHECK_PORT(162, "SNMP Trap");
        CHECK_PORT(500, "IKE");
        CHECK_PORT(514, "Syslog");
        CHECK_PORT(1194, "OpenVPN");
        CHECK_PORT(1701, "L2TP");
        CHECK_PORT(1812, "RADIUS");
        CHECK_PORT(1813, "RADIUS Accounting");
        CHECK_PORT(4500, "IPSec NAT Traversal");
        CHECK_PORT(5353, "mDNS");
        CHECK_PORT(5060, "SIP");
    }

    #undef CHECK_PORT

    if (packet->payload_length > 0) {
        if (strncmp(packet->payload, "GET ", 4) == 0 ||
            strncmp(packet->payload, "POST ", 5) == 0 ||
            strncmp(packet->payload, "HTTP/", 5) == 0) {
            return "HTTP";
        }
        if (strncmp(packet->payload, "SSH-", 4) == 0) {
            return "SSH";
        }
        if (strncmp(packet->payload, "SMTP", 4) == 0) {
            return "SMTP";
        }
    }

    return "Unknown";
}

void classify_by_ports(const ParsedPacket *packet, char *src_port, char *dst_port) {
    snprintf(src_port, 16, "port %u", packet->src_port);
    snprintf(dst_port, 16, "port %u", packet->dst_port);
}


void classify_by_country(const ParsedPacket *packet, char *src_country, char *dst_country) {
    int gai_error, mmdb_error;
    MMDB_lookup_result_s result;
    MMDB_entry_data_s entry_data;

    void lookup_country(const char *ip, char *country) {
        result = MMDB_lookup_string(&mmdb, ip, &gai_error, &mmdb_error);
        if (gai_error != 0) {
            fprintf(stderr, "Error from getaddrinfo for IP %s - %s\n", ip, gai_strerror(gai_error));
            snprintf(country, 32, "Unknown");
        } else if (mmdb_error != MMDB_SUCCESS) {
            fprintf(stderr, "Error from libmaxminddb for IP %s: %s\n", ip, MMDB_strerror(mmdb_error));
            snprintf(country, 32, "Unknown");
        } else if (result.found_entry) {
            if (MMDB_get_value(&result.entry, &entry_data, "country", "names", "en", NULL) == MMDB_SUCCESS && entry_data.has_data) {
                if (entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
                    snprintf(country, 32, "%.*s", entry_data.data_size, entry_data.utf8_string);
                }
            } else {
                strncpy(country, "Unknown", 32);
            }
        } else {
            strncpy(country, "Unknown", 32);
        }
    }

    lookup_country(packet->src_ip, src_country);
    lookup_country(packet->dst_ip, dst_country);
}

const char *classify_between_countries(const ParsedPacket *packet, CountryPair *country_pairs, int num_pairs, const char *src_country, const char *dst_country) {
    static char src_dst_pair[65];  // Static buffer to avoid dynamic allocation

    snprintf(src_dst_pair, sizeof(src_dst_pair), "%s-%s", src_country, dst_country);
    
    for (int i = 0; i < num_pairs; i++) {
        if (strcmp(src_country, country_pairs[i].src_country) == 0 && 
            strcmp(dst_country, country_pairs[i].dst_country) == 0) {
            return src_dst_pair;
        }
    }

    return NULL;
}

LinkMetrics calculate_link_metrics(const ParsedPacket *packet) {
    LinkMetrics metrics;
    
    double duration = (packet->ts.tv_sec - packet->start_time.tv_sec) + 
                      (packet->ts.tv_usec - packet->start_time.tv_usec) / 1e6;

    metrics.link_rate_bps = (packet->total_bytes * 8) / duration;
    metrics.link_rate_Bps = packet->total_bytes / duration;
    metrics.packet_rate_pps = packet->packet_count / duration;

    metrics.total_packets_count = packet->packet_count;
    metrics.total_bytes = packet->total_bytes;
    metrics.total_packets_recieved = packet->packets_received;
    metrics.packets_dropped = packet->packets_dropped;
    metrics.packets_if_dropped = packet->packets_if_dropped;

    return metrics;
}

void print_parsed_packet(const ParsedPacket *packet) {
    printf("Timestamp: %ld.%06ld\n", packet->ts.tv_sec, packet->ts.tv_usec);
    printf("Packet Size: %u bytes\n", packet->packet_size);
    printf("Source IP: %s\n", packet->src_ip);
    printf("Destination IP: %s\n", packet->dst_ip);
    printf("Protocol: %u\n", packet->protocol);
    printf("Source Port: %u\n", packet->src_port);
    printf("Destination Port: %u\n", packet->dst_port);
    printf("Payload Length: %d bytes\n", packet->payload_length);
    printf("Packet Count: %u\n", packet->packet_count);
    printf("Total Bytes: %lu bytes\n", packet->total_bytes);
    printf("Packets Dropped: %u\n", packet->packets_dropped);
    printf("Packets Received: %lu\n", packet->packets_received);
    printf("Packets Dropped by Interface: %u\n", packet->packets_if_dropped);
    printf("Capture Start Time: %ld.%06ld\n", packet->start_time.tv_sec, packet->start_time.tv_usec);
}
