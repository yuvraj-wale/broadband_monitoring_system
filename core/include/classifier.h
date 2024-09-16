#ifndef CLASSIFIER_H
#define CLASSIFIER_H

#include "parser.h"
#include "capture.h"
#include <stdio.h>
#include <maxminddb.h>
#include <string.h>

extern MMDB_s mmdb;

typedef struct {
    double link_rate_bps;
    double link_rate_Bps;
    double packet_rate_pps;
    uint32_t total_packets_count;
    uint64_t total_bytes;
    uint32_t total_packets_recieved;
    uint32_t packets_dropped;
    uint32_t packets_if_dropped;
} LinkMetrics;

void initialize_geoip(const char *db_path);
void cleanup_geoip();
void print_parsed_packet(const ParsedPacket *packet);
const char *classify_by_encryption(const ParsedPacket *packet);
const char *classify_by_protocol(const ParsedPacket *packet);
const char *classify_by_application_protocol(const ParsedPacket *packet);
void classify_by_ports(const ParsedPacket *packet, char *src_port, char *dst_port);
void classify_by_country(const ParsedPacket *packet, char *src_country, char *dst_country);
const char *classify_between_countries(const ParsedPacket *packet, CountryPair *country_pairs, int num_pairs, const char *src_country, const char *dst_country);
LinkMetrics calculate_link_metrics(const ParsedPacket *packet);

#endif
