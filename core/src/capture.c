// #include <pcap.h>
// #include <stdio.h>
// #include <signal.h>
// #include <stdlib.h>
// #include <stdbool.h>
// #include <string.h>
// #include <sys/time.h>
// #include <arpa/inet.h>
// #include <netinet/ip.h>
// #include <netinet/tcp.h>
// #include <netinet/udp.h>
// #include "capture.h"
// #include "hashtable.h"
// #include "parser.h"
// #include "classifier.h"

// #define INITIAL_SIZE 1024

// volatile int packet_count = 0;
// volatile uint64_t total_bytes = 0;
// pcap_t *handle;
// struct pcap_stat stats;
// struct timeval start_time;
// ClassifiedData *classified_data;

// void initialize_geoip(const char *db_path);
// void cleanup_geoip();

// ClassifiedData* get_classified_data() {
//     return &classified_data;
// }

// void aggregate(const ParsedPacket *packet, CountryPair *country_pairs, int num_pairs)
// {

//     char src_port[16];
//     char dst_port[16];
//     classify_by_ports(packet, src_port, dst_port);

//     char src_country[32];
//     char dst_country[32];
//     classify_by_country(packet, src_country, dst_country);

//     LinkMetrics metrics = calculate_link_metrics(packet);

//     // protocol
//     increment(classified_data->protocol, classify_by_protocol(packet));

//     // application protocol
//     increment(classified_data->application_protocol, classify_by_application_protocol(packet));

//     // encryption status
//     increment(classified_data->encryption, classify_by_encryption(packet));

//     // ports
//     increment(classified_data->port, src_port);
//     increment(classified_data->port, dst_port);

//     // countries
//     increment(classified_data->country, src_country);
//     increment(classified_data->country, dst_country);

//     // target countries
//     const char *src_dst_pair = classify_between_countries(packet, country_pairs, num_pairs);
//     if (src_dst_pair)
//     {
//         increment(classified_data->target_countries, src_dst_pair);
//         free((void*)src_dst_pair);
//     }

//     // metrics
//     update(classified_data->metrics, "link_rate_bps", (uint32_t)metrics.link_rate_bps);
//     update(classified_data->metrics, "link_rate_Bps", (uint32_t)metrics.link_rate_Bps);
//     update(classified_data->metrics, "packet_rate_pps", (uint32_t)metrics.packet_rate_pps);
//     update(classified_data->metrics, "total_packets_count", metrics.total_packets_count);
//     update(classified_data->metrics, "total_bytes", metrics.total_bytes);
//     update(classified_data->metrics, "total_packets_recieved", metrics.total_packets_recieved);
//     update(classified_data->metrics, "packets_dropped", metrics.packets_dropped);
//     update(classified_data->metrics, "packets_if_dropped", metrics.packets_if_dropped);
// }

// void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet)
// {
//     InputData *context = (InputData *)user_data;
//     if (pcap_stats(handle, &stats) != 0)
//     {
//         fprintf(stderr, "Error getting stats: %s\n", pcap_geterr(handle));
//     }
//     if (is_ip_packet(packet))
//     {
//         packet_count++;
//         total_bytes += pkthdr->len;
//         ParsedPacket parsed_packet = parse_packet(pkthdr, packet, packet_count, total_bytes, &stats, &start_time);
//         if (parsed_packet.protocol != 0 && parsed_packet.packet_size > 0)
//         {
//             aggregate(&parsed_packet, context->country_pairs, context->num_pairs);
//         }
//     }
// }

// void stop_packet_capture(int signum)
// {
//     struct pcap_stat stats;

//     if (pcap_stats(handle, &stats) != 0) {
//         fprintf(stderr, "Error getting stats: %s\n", pcap_geterr(handle));
//     } else {
//         printf("************************************\n");
//         printf("*        Packet Capture Stats      *\n");
//         printf("************************************\n\n");

//         printf("Total Packets Captured         : %d\n", packet_count);
//         printf("Total Packets Received         : %u\n", stats.ps_recv);
//         printf("Total Packets Dropped          : %u\n", stats.ps_drop);
//         printf("Total Packets Dropped by Iface : %u\n", stats.ps_ifdrop);
//         printf("\n");
//     }

//     print_classified_data(classified_data);

//     free_table(classified_data->protocol);
//     free_table(classified_data->application_protocol);
//     free_table(classified_data->encryption);
//     free_table(classified_data->port);
//     free_table(classified_data->country);
//     free_table(classified_data->metrics);
//     free_table(classified_data->target_countries);
//     free(classified_data);

//     pcap_breakloop(handle);

//     cleanup_geoip();
// }

// void start_packet_capture(const char *device, const char *filter_expr, int packet_count, int timeout, CountryPair *country_pairs, int num_pairs)
// {
//     printf("Packet Capture Started at %s for %s ...\n", device, filter_expr);

//     char errbuf[PCAP_ERRBUF_SIZE];
//     initialize_geoip("/home/yuraj/ip_link_analyser/core/data/GeoLite2-Country.mmdb");

//     classified_data = malloc(sizeof(ClassifiedData));
//     classified_data->protocol = create_table(INITIAL_SIZE);
//     classified_data->application_protocol = create_table(INITIAL_SIZE);
//     classified_data->encryption = create_table(INITIAL_SIZE);
//     classified_data->port = create_table(INITIAL_SIZE);
//     classified_data->country = create_table(INITIAL_SIZE);
//     classified_data->metrics = create_table(INITIAL_SIZE);
//     classified_data->target_countries = create_table(INITIAL_SIZE);

//     handle = pcap_open_live(device, 65535, 1, timeout, errbuf);
//     if (handle == NULL)
//     {
//         fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
//         return;
//     }

//     if (filter_expr)
//     {
//         struct bpf_program fp;
//         if (pcap_compile(handle, &fp, filter_expr, 0, PCAP_NETMASK_UNKNOWN) == -1)
//         {
//             fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_expr, pcap_geterr(handle));
//             return;
//         }
//         if (pcap_setfilter(handle, &fp) == -1)
//         {
//             fprintf(stderr, "Couldn't install filter %s: %s\n", filter_expr, pcap_geterr(handle));
//             return;
//         }
//         pcap_freecode(&fp);
//         printf("Filter applied: %s\n", filter_expr);
//     }

//     signal(SIGINT, stop_packet_capture);

//     gettimeofday(&start_time, NULL);

//     InputData context = {
//         .country_pairs = country_pairs,
//         .num_pairs = num_pairs
//     };

//     pcap_loop(handle, packet_count, packet_handler, (u_char *)&context);

//     pcap_close(handle);
// }


#include <pcap.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pthread.h>
#include "capture.h"
#include "hashtable.h"
#include "parser.h"
#include "classifier.h"

#define INITIAL_SIZE 1024

volatile bool capture_running = false;
volatile int packet_count = 0;
volatile uint64_t total_bytes = 0;
pcap_t *handle;
struct pcap_stat stats;
struct timeval start_time;
ClassifiedData *classified_data;
pthread_t capture_thread;
pthread_mutex_t data_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    const char *device;
    const char *filter_expr;
    int packet_count;
    int timeout;
    CountryPair *country_pairs;
    int num_pairs;
} ThreadInputData;

void initialize_geoip(const char *db_path);
void cleanup_geoip();

ClassifiedData* get_classified_data() {
    return classified_data;
}

void aggregate(const ParsedPacket *packet, CountryPair *country_pairs, int num_pairs) {
    char src_port[16];
    char dst_port[16];
    classify_by_ports(packet, src_port, dst_port);

    char src_country[32];
    char dst_country[32];
    classify_by_country(packet, src_country, dst_country);

    LinkMetrics metrics = calculate_link_metrics(packet);

    pthread_mutex_lock(&data_mutex);

    increment(classified_data->protocol, classify_by_protocol(packet));
    increment(classified_data->application_protocol, classify_by_application_protocol(packet));
    increment(classified_data->encryption, classify_by_encryption(packet));
    increment(classified_data->port, src_port);
    increment(classified_data->port, dst_port);
    increment(classified_data->country, src_country);
    increment(classified_data->country, dst_country);

    printf("@@@@@@@@@@@@@@ %s @@@@@@@@@@@@\n", country_pairs[0].src_country);
    printf("@@@@@@@@@@@@@@ %s @@@@@@@@@@@@\n", country_pairs[0].dst_country);

    const char *src_dst_pair = classify_between_countries(packet, country_pairs, num_pairs, src_country, dst_country);
    if (src_dst_pair) {
        increment(classified_data->target_countries, src_dst_pair);
    }

    update(classified_data->metrics, "link_rate_bps", (uint32_t)metrics.link_rate_bps);
    update(classified_data->metrics, "link_rate_Bps", (uint32_t)metrics.link_rate_Bps);
    update(classified_data->metrics, "packet_rate_pps", (uint32_t)metrics.packet_rate_pps);
    update(classified_data->metrics, "total_packets_count", metrics.total_packets_count);
    update(classified_data->metrics, "total_bytes", metrics.total_bytes);
    update(classified_data->metrics, "total_packets_recieved", metrics.total_packets_recieved);
    update(classified_data->metrics, "packets_dropped", metrics.packets_dropped);
    update(classified_data->metrics, "packets_if_dropped", metrics.packets_if_dropped);

    pthread_mutex_unlock(&data_mutex);
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    InputData *context = (InputData *)user_data;
    if (pcap_stats(handle, &stats) != 0) {
        fprintf(stderr, "Error getting stats: %s\n", pcap_geterr(handle));
    }
    if (is_ip_packet(packet)) {
        packet_count++;
        total_bytes += pkthdr->len;
        ParsedPacket parsed_packet = parse_packet(pkthdr, packet, packet_count, total_bytes, &stats, &start_time);
        if (parsed_packet.protocol != 0 && parsed_packet.packet_size > 0) {
            aggregate(&parsed_packet, context->country_pairs, context->num_pairs);
        }
    }
}

void stop_packet_capture(int signum) {
    capture_running = false;
    struct pcap_stat stats;

    if (pcap_stats(handle, &stats) != 0) {
        fprintf(stderr, "Error getting stats: %s\n", pcap_geterr(handle));
    } else {
        printf("************************************\n");
        printf("*        Packet Capture Stats      *\n");
        printf("************************************\n\n");

        printf("Total Packets Captured         : %d\n", packet_count);
        printf("Total Packets Received         : %u\n", stats.ps_recv);
        printf("Total Packets Dropped          : %u\n", stats.ps_drop);
        printf("Total Packets Dropped by Iface : %u\n", stats.ps_ifdrop);
        printf("\n");
    }

    print_classified_data(classified_data);

    pcap_breakloop(handle);
    cleanup_capture();
}

void* start_packet_capture_thread(void *arg) {
    ThreadInputData *input_data = (ThreadInputData *)arg;
    capture_running=true;
    start_packet_capture(input_data->device, input_data->filter_expr, input_data->packet_count, input_data->timeout, input_data->country_pairs, input_data->num_pairs);

    free(input_data->device);
    free(input_data->filter_expr);
    // free(input_data->packet_count);
    // free(input_data->timeout);
    // free(input_data->num_pairs);
    free(input_data->country_pairs);
    free(input_data);
    return NULL;
}

void start_packet_capture(const char *device, const char *filter_expr, int packet_count, int timeout, CountryPair *country_pairs, int num_pairs) {
    printf("Packet Capture Started at %s for %s ...\n", device, filter_expr);
    capture_running=true;
    // cleanup_capture();

    char errbuf[PCAP_ERRBUF_SIZE];
    initialize_geoip("../core/data/GeoLite2-Country.mmdb");

    pthread_mutex_lock(&data_mutex);

    classified_data = malloc(sizeof(ClassifiedData));
    if (classified_data == NULL) {
        fprintf(stderr, "Failed to allocate memory for classified_data\n");
        pthread_mutex_unlock(&data_mutex);
        return;
    }
    classified_data->protocol = create_table(INITIAL_SIZE);
    classified_data->application_protocol = create_table(INITIAL_SIZE);
    classified_data->encryption = create_table(INITIAL_SIZE);
    classified_data->port = create_table(INITIAL_SIZE);
    classified_data->country = create_table(INITIAL_SIZE);
    classified_data->metrics = create_table(INITIAL_SIZE);
    classified_data->target_countries = create_table(INITIAL_SIZE);

    pthread_mutex_unlock(&data_mutex);

    handle = pcap_open_live(device, 65535, 1, timeout, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        cleanup_capture();
        return;
    }

    if (filter_expr) {
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, filter_expr, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_expr, pcap_geterr(handle));
            return;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter_expr, pcap_geterr(handle));
            return;
        }
        pcap_freecode(&fp);
        printf("Filter applied: %s\n", filter_expr);
    }

    signal(SIGINT, stop_packet_capture);

    gettimeofday(&start_time, NULL);

    InputData context = {
        .country_pairs = country_pairs,
        .num_pairs = num_pairs
    };

    pcap_loop(handle, packet_count, packet_handler, (u_char *)&context);

    pcap_close(handle);
    capture_running = false;
    printf("Handle closed..");
}

void start_capture_in_thread(const char *device, const char *filter_expr, int packet_count, int timeout, CountryPair *country_pairs, int num_pairs) {
    if (capture_running) {
        fprintf(stderr, "Capture already in progress. Cannot start a new one.\n");
        return;
    }
    ThreadInputData *input_data = malloc(sizeof(ThreadInputData));
    input_data->device = strdup(device);
    input_data->filter_expr = strdup(filter_expr);
    input_data->packet_count = packet_count;
    input_data->timeout = timeout;
    input_data->country_pairs = malloc(num_pairs * sizeof(CountryPair));
    if (input_data->country_pairs == NULL) {
        fprintf(stderr, "Error allocating memory for country_pairs\n");
        free(input_data->device);
        free(input_data->filter_expr);
        free(input_data->packet_count);
        free(input_data->timeout);
        free(input_data->num_pairs);
        free(input_data->country_pairs);
        free(input_data);
        return;
    }
    memcpy(input_data->country_pairs, country_pairs, num_pairs * sizeof(CountryPair));    
    input_data->num_pairs = num_pairs;

    printf("Starting capture thread with data:\n");
    printf("Device: %s\n", input_data->device);
    printf("Filter: %s\n", input_data->filter_expr);
    printf("Number of country pairs: %d\n", input_data->num_pairs);
    for (int i = 0; i < input_data->num_pairs; i++) {
        printf("Pair %d: %s -> %s\n", i, input_data->country_pairs[i].src_country, input_data->country_pairs[i].dst_country);
    }

    if (pthread_create(&capture_thread, NULL, start_packet_capture_thread, (void *)input_data) != 0) {
        fprintf(stderr, "Error creating capture thread\n");
        free(input_data->device);
        free(input_data->filter_expr);
        free(input_data->packet_count);
        free(input_data->timeout);
        free(input_data->num_pairs);
        free(input_data->country_pairs);
        free(input_data);
    }
}

void stop_capture_thread() {
    if (!capture_running) {
        fprintf(stderr, "No capture in progress. Nothing to stop.\n");
        return;
    }
    stop_packet_capture(SIGINT);
    pthread_join(capture_thread, NULL);
}

void cleanup_capture() {

    pthread_mutex_lock(&data_mutex);

    if (classified_data != NULL) {
        free_table(classified_data->protocol);
        free_table(classified_data->application_protocol);
        free_table(classified_data->encryption);
        free_table(classified_data->port);
        free_table(classified_data->country);
        free_table(classified_data->metrics);
        free_table(classified_data->target_countries);
        free(classified_data);
        classified_data = NULL;
    }

    packet_count = 0;
    total_bytes = 0;

    memset(&stats, 0, sizeof(struct pcap_stat));

    memset(&start_time, 0, sizeof(struct timeval));

    cleanup_geoip();

    pthread_mutex_unlock(&data_mutex);

    printf("Capture cleanup completed.\n");
}

