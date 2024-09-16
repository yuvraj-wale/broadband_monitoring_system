#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

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
    // Add more categories as needed
} ClassifiedData;

unsigned long hash(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    return hash;
}

HashTable *create_table(size_t size) {
    HashTable *table = malloc(sizeof(HashTable));
    table->size = size;
    table->table = calloc(size, sizeof(Entry *));
    return table;
}

void free_table(HashTable *table) {
    if (table == NULL) return;
    for (size_t i = 0; i < table->size; i++) {
        Entry *entry = table->table[i];
        while (entry) {
            Entry *temp = entry;
            entry = entry->next;
            free(temp->key);
            free(temp);
        }
        table->table[i] = NULL;
    }
    free(table->table);
    table->table = NULL;
    free(table);
}

uint32_t get(HashTable *table, const char *key) {
    unsigned long index = hash(key) % table->size;
    Entry *entry = table->table[index];
    while (entry) {
        if (strcmp(entry->key, key) == 0) {
            return entry->value;
        }
        entry = entry->next;
    }
    return 0; // Return 0 if key is not found
}

void update(HashTable *table, const char *key, uint32_t value) {
    unsigned long index = hash(key) % table->size;
    Entry *entry = table->table[index];
    while (entry) {
        if (strcmp(entry->key, key) == 0) {
            entry->value = value;
            return;
        }
        entry = entry->next;
    }
    // Key not found, create a new entry
    Entry *new_entry = malloc(sizeof(Entry));
    new_entry->key = strdup(key);
    new_entry->value = value;
    new_entry->next = table->table[index];
    table->table[index] = new_entry;
}

void increment(HashTable *table, const char *key) {
    unsigned long index = hash(key) % table->size;
    Entry *entry = table->table[index];
    while (entry) {
        if (strcmp(entry->key, key) == 0) {
            entry->value++;
            return;
        }
        entry = entry->next;
    }
    // Key not found, create a new entry
    Entry *new_entry = malloc(sizeof(Entry));
    new_entry->key = strdup(key);
    new_entry->value = 1;
    new_entry->next = table->table[index];
    table->table[index] = new_entry;
}

void print_table(HashTable *table) {
    for (size_t i = 0; i < table->size; i++) {
        Entry *entry = table->table[i];
        while (entry) {
            printf("%-25s: %u\n", entry->key, entry->value);
            entry = entry->next;
        }
    }
}

void print_classified_data(ClassifiedData *data) {
    printf("************************************\n");
    printf("*        Classified Data           *\n");
    printf("************************************\n\n");

    printf("Transport Layer Protocols:\n");
    printf("----------------------------\n");
    print_table(data->protocol);
    printf("\n");

    printf("Application Layer Protocols:\n");
    printf("-----------------------------\n");
    print_table(data->application_protocol);
    printf("\n");

    printf("Encryption Status:\n");
    printf("-----------------------------\n");
    print_table(data->encryption);
    printf("\n");

    printf("Port Analysis:\n");
    printf("-----------------------------\n");
    print_table(data->port);
    printf("\n");

    printf("Countries:\n");
    printf("-----------------------------\n");
    print_table(data->country);
    printf("\n");

    printf("Target Countries Traffic:\n");
    printf("-----------------------------\n");
    print_table(data->target_countries);
    printf("\n");

    printf("Link Metrics:\n");
    printf("-----------------------------\n");
    print_table(data->metrics);
    printf("\n");
    // Print other categories as needed
}

void free_classified_data(ClassifiedData *data) {
    if (data == NULL) return;

    free_table(data->protocol);
    free_table(data->application_protocol);
    free_table(data->encryption);
    free_table(data->port);
    free_table(data->country);
    free_table(data->metrics);
    free_table(data->target_countries);
    
    free(data);
}

