#ifndef HASHTABLE_H
#define HASHTABLE_H

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

unsigned long hash(const char *str);
HashTable *create_table(size_t size);
void free_table(HashTable *table);
uint32_t get(HashTable *table, const char *key);
void increment(HashTable *table, const char *key);
void print_table(HashTable *table);
void print_classified_data(ClassifiedData *data);

#endif
