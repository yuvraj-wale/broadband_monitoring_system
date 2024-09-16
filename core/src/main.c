#include "capture.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_COUNTRY_PAIRS 100

int main(int argc, char *argv[]) {
    const char *device = NULL;
    const char *filter_expr = NULL;
    int packet_count = 0;
    int timeout = 0;
    CountryPair country_pairs[MAX_COUNTRY_PAIRS];
    int num_pairs = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--i") == 0 && i + 1 < argc) {
            device = argv[++i];
        } else if (strcmp(argv[i], "--f") == 0 && i + 1 < argc) {
            filter_expr = argv[++i];
        } else if (strcmp(argv[i], "--c") == 0 && i + 1 < argc) {
            packet_count = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--t") == 0 && i + 1 < argc) {
            timeout = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--pair") == 0 && i + 2 < argc) {
            if (num_pairs < MAX_COUNTRY_PAIRS) {
                strncpy(country_pairs[num_pairs].src_country, argv[++i], 31);
                country_pairs[num_pairs].src_country[31] = '\0';
                strncpy(country_pairs[num_pairs].dst_country, argv[++i], 31);
                country_pairs[num_pairs].dst_country[31] = '\0';
                num_pairs++;
            } else {
                fprintf(stderr, "Maximum number of country pairs reached.\n");
            }
        }
    }

    if (!device) {
        fprintf(stderr, "Usage: %s --i <network interface> [--f <filter expression>] [--c <packet count>] [--t <timeout in ms>] [--pair <src country> <dst country> ...]\n", argv[0]);
        return 1;
    }

    start_packet_capture(device, filter_expr, packet_count, timeout, country_pairs, num_pairs);

    return 0;
}
