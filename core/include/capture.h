#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>
#include "parser.h"
#include "hashtable.h"
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

typedef struct {
    char src_country[32];
    char dst_country[32];
} CountryPair;

typedef struct {
    CountryPair *country_pairs;
    int num_pairs;
} InputData;

void start_capture_in_thread(const char *device, const char *filter_expr, int packet_count, int timeout, CountryPair *country_pairs, int num_pairs);
void stop_capture_thread();
void close_packet_capture();
ClassifiedData* get_classified_data();

#endif
