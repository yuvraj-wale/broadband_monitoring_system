from cffi import FFI
import logging

logging.basicConfig(level=logging.DEBUG)

ffi = FFI()

ffi.cdef("""
typedef struct Entry {
    char *key;
    uint32_t value;
    struct Entry *next;
} Entry;

typedef struct HashTable {
    Entry **table;
    size_t size;
} HashTable;

typedef struct {
    HashTable *protocol;
    HashTable *application_protocol;
    HashTable *encryption;
    HashTable *port;
    HashTable *country;
    HashTable *metrics;
    HashTable *target_countries;
} ClassifiedData;

typedef struct {
    char src_country[32];
    char dst_country[32];
} CountryPair;

void start_capture_in_thread(const char *device, const char *filter_expr, int packet_count, int timeout, CountryPair *country_pairs, int num_pairs);
void stop_capture_thread();
void close_packet_capture();
ClassifiedData* get_classified_data();
""")

lib = ffi.dlopen("../core/libip_link_analyzer.so")

def convert_hash_table(hash_table):
    result = {}
    for i in range(hash_table.size):
        entry = hash_table.table[i]
        while entry:
            if entry.key:
                key = ffi.string(entry.key).decode('utf-8')
                result[key] = entry.value
            entry = entry.next
    return result

def convert_classified_data(data):
    return {
        'protocol': convert_hash_table(data.protocol),
        'application_protocol': convert_hash_table(data.application_protocol),
        'encryption': convert_hash_table(data.encryption),
        'port': convert_hash_table(data.port),
        'country': convert_hash_table(data.country),
        'metrics': convert_hash_table(data.metrics),
        'target_countries': convert_hash_table(data.target_countries),
    }

def start_packet_capture(device, filter_expr, packet_count, timeout, country_pairs):
    num_pairs = len(country_pairs)
    country_pairs_c = ffi.new("CountryPair[]", num_pairs)
    
    for i, pair in enumerate(country_pairs):
        src_country_len = len(pair['src_country'])
        dst_country_len = len(pair['dst_country'])
        
        # Copy the strings to the structure ensuring they are null-terminated
        ffi.memmove(country_pairs_c[i].src_country, pair['src_country'].encode('utf-8'), src_country_len + 1)
        ffi.memmove(country_pairs_c[i].dst_country, pair['dst_country'].encode('utf-8'), dst_country_len + 1)
    
    print("Country pairs:")
    for i in range(num_pairs):
        src_country = ffi.string(country_pairs_c[i].src_country).decode('utf-8')
        dst_country = ffi.string(country_pairs_c[i].dst_country).decode('utf-8')
        print(f"{i}: {src_country} -> {dst_country}")

    print("Starting capture in thread...")
    lib.start_capture_in_thread(device.encode('utf-8'), filter_expr.encode('utf-8'), packet_count, timeout, country_pairs_c, num_pairs)
    print("Capture started.")

def stop_packet_capture():
    lib.stop_capture_thread()

# def close_packet_capture():
#     lib.close_packet_capture()

def get_classified_data():
    try:
        data = lib.get_classified_data()
        return convert_classified_data(data)
    except Exception as e:
        logging.error(f"Error getting classified data: {e}")
        return {}