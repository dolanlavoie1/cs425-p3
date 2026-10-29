#ifndef LAB_H
#define LAB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/*
 * Every address in this file is a uint32_t in host byte order, so the first
 * octet of 192.168.1.10 is the most significant byte: 0xC0A8010A.
 */

/** Room for the longest dotted quad, "255.255.255.255", and its '\0'. */
#define IP_STR_LEN 16

/** Room for the longest CIDR string, "255.255.255.255/32", and its '\0'. */
#define CIDR_STR_LEN 19

/** Room for an interface name; IFNAMSIZ on Linux, including the '\0'. */
#define DEV_NAME_LEN 16

/** An address block in CIDR notation: an address and a prefix length. */
typedef struct {
  uint32_t addr;  /**< any address in the block, host byte order */
  uint8_t prefix; /**< 0 to 32 */
} cidr_t;

/** One entry in a forwarding table. */
typedef struct {
  cidr_t dest;            /**< destination block; host bits must be zero */
  uint32_t gateway;       /**< next hop, or 0 when the block is directly connected */
  char dev[DEV_NAME_LEN]; /**< outgoing interface, for example "eth0" */
} route_t;

/** A forwarding table. Its layout is private to lab.c. */
typedef struct fwd_table fwd_table_t;

bool ip_parse(const char *text, uint32_t *addr);
void ip_format(uint32_t addr, char out[IP_STR_LEN]);
bool cidr_parse(const char *text, cidr_t *block);
void cidr_format(cidr_t block, char out[CIDR_STR_LEN]);

uint32_t cidr_mask(uint8_t prefix);
uint32_t cidr_network(cidr_t block);
uint32_t cidr_broadcast(cidr_t block);
uint32_t cidr_first_host(cidr_t block);
uint32_t cidr_last_host(cidr_t block);
uint64_t cidr_host_count(cidr_t block);
bool cidr_contains(cidr_t block, uint32_t addr);
bool cidr_is_network(cidr_t block);
bool cidr_subnet(cidr_t block, uint32_t n, uint32_t i, cidr_t *out);

bool route_parse(const char *line, route_t *route);
fwd_table_t *table_create(void);
void table_destroy(fwd_table_t *table);
size_t table_count(const fwd_table_t *table);
bool table_add(fwd_table_t *table, const route_t *route);
bool table_load(fwd_table_t *table, FILE *in, size_t *bad_line);
const route_t *table_lookup(const fwd_table_t *table, uint32_t dest);

#endif // LAB_H
