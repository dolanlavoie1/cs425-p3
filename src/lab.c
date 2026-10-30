#include "lab.h"

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct fwd_table {
  route_t *routes;
  size_t count;
  size_t capacity;
};

bool ip_parse(const char *text, uint32_t *addr)
{
  uint32_t value = 0;
  const char *cursor = text;

  if (text == NULL || addr == NULL) {
    return false;
  }

  for (unsigned int octet_index = 0; octet_index < 4; octet_index++) {
    unsigned int octet = 0;
    unsigned int digit_count = 0;

    if (*cursor < '0' || *cursor > '9') {
      return false;
    }
    if (*cursor == '0' && cursor[1] >= '0' && cursor[1] <= '9') {
      return false;
    }

    while (*cursor >= '0' && *cursor <= '9') {
      octet = octet * 10U + (unsigned int)(*cursor - '0');
      digit_count++;
      if (digit_count > 3 || octet > 255U) {
        return false;
      }
      cursor++;
    }

    value = (value << 8) | (uint32_t)octet;
    if (octet_index < 3) {
      if (*cursor != '.') {
        return false;
      }
      cursor++;
    } else if (*cursor != '\0') {
      return false;
    }
  }

  *addr = value;
  return true;
}

void ip_format(uint32_t addr, char out[IP_STR_LEN])
{
  (void)snprintf(out, IP_STR_LEN, "%u.%u.%u.%u",
                 (unsigned int)((addr >> 24) & 0xffU),
                 (unsigned int)((addr >> 16) & 0xffU),
                 (unsigned int)((addr >> 8) & 0xffU),
                 (unsigned int)(addr & 0xffU));
}

bool cidr_parse(const char *text, cidr_t *block)
{
  const char *slash;
  const char *prefix_text;
  size_t address_length;
  uint32_t address;
  unsigned int prefix = 0;
  unsigned int digit_count = 0;
  char address_text[IP_STR_LEN];

  if (text == NULL || block == NULL) {
    return false;
  }

  slash = text;
  while (*slash != '\0' && *slash != '/') {
    slash++;
  }
  if (*slash != '/') {
    return false;
  }

  address_length = (size_t)(slash - text);
  if (address_length == 0 || address_length >= IP_STR_LEN) {
    return false;
  }
  for (size_t index = 0; index < address_length; index++) {
    address_text[index] = text[index];
  }
  address_text[address_length] = '\0';
  if (!ip_parse(address_text, &address)) {
    return false;
  }

  prefix_text = slash + 1;
  if (*prefix_text == '\0' ||
      (*prefix_text == '0' && prefix_text[1] != '\0')) {
    return false;
  }
  while (*prefix_text >= '0' && *prefix_text <= '9') {
    prefix = prefix * 10U + (unsigned int)(*prefix_text - '0');
    digit_count++;
    if (digit_count > 2 || prefix > 32U) {
      return false;
    }
    prefix_text++;
  }
  if (*prefix_text != '\0') {
    return false;
  }

  block->addr = address;
  block->prefix = (uint8_t)prefix;
  return true;
}

void cidr_format(cidr_t block, char out[CIDR_STR_LEN])
{
  char address[IP_STR_LEN];
  unsigned int prefix = block.prefix > 32U ? 32U : (unsigned int)block.prefix;

  ip_format(block.addr, address);
  (void)snprintf(out, CIDR_STR_LEN, "%s/%u", address, prefix);
}

uint32_t cidr_mask(uint8_t prefix)
{
  if (prefix == 0) {
    return 0;
  }
  if (prefix >= 32) {
    return UINT32_MAX;
  }
  return UINT32_MAX << (32U - prefix);
}

uint32_t cidr_network(cidr_t block)
{
  return block.addr & cidr_mask(block.prefix);
}

uint32_t cidr_broadcast(cidr_t block)
{
  return cidr_network(block) | ~cidr_mask(block.prefix);
}

uint32_t cidr_first_host(cidr_t block)
{
  uint8_t prefix = block.prefix > 32 ? 32 : block.prefix;

  if (prefix >= 31) {
    return cidr_network(block);
  }
  return cidr_network(block) + 1U;
}

uint32_t cidr_last_host(cidr_t block)
{
  uint8_t prefix = block.prefix > 32 ? 32 : block.prefix;

  if (prefix >= 31) {
    return cidr_broadcast(block);
  }
  return cidr_broadcast(block) - 1U;
}

uint64_t cidr_host_count(cidr_t block)
{
  uint8_t prefix = block.prefix > 32 ? 32 : block.prefix;

  if (prefix == 31) {
    return 2;
  }
  if (prefix == 32) {
    return 1;
  }
  return (UINT64_C(1) << (32U - prefix)) - 2;
}

bool cidr_contains(cidr_t block, uint32_t addr)
{
  uint32_t mask = cidr_mask(block.prefix);

  return (addr & mask) == (block.addr & mask);
}

bool cidr_is_network(cidr_t block)
{
  return cidr_network(block) == block.addr;
}

bool cidr_subnet(cidr_t block, uint32_t n, uint32_t i, cidr_t *out)
{
  uint8_t prefix = block.prefix;
  uint32_t extra_bits = 0;
  uint32_t remaining;
  uint8_t new_prefix;
  cidr_t result;

  if (out == NULL || block.prefix > 32 || !cidr_is_network(block) || n == 0 ||
      (n & (n - 1U)) != 0 || i >= n) {
    return false;
  }

  remaining = n;
  while (remaining > 1) {
    remaining >>= 1;
    extra_bits++;
  }
  if (prefix > 32 || extra_bits > 32U - prefix) {
    return false;
  }

  new_prefix = (uint8_t)(prefix + extra_bits);
  result.prefix = new_prefix;
  result.addr = block.addr;
  if (i != 0 && new_prefix < 32) {
    result.addr += i << (32U - new_prefix);
  } else if (i != 0) {
    result.addr += i;
  }
  *out = result;
  return true;
}

bool route_parse(const char *line, route_t *route)
{
  const char *tokens[3] = {NULL, NULL, NULL};
  size_t lengths[3] = {0, 0, 0};
  size_t token_count = 0;
  const char *cursor;
  route_t parsed;
  char destination[CIDR_STR_LEN];
  char gateway[IP_STR_LEN];
  cidr_t destination_block;
  uint32_t gateway_address;

  if (line == NULL || route == NULL) {
    return false;
  }

  cursor = line;
  while (*cursor != '\0') {
    while (*cursor != '\0' && isspace((unsigned char)*cursor)) {
      cursor++;
    }
    if (*cursor == '\0') {
      break;
    }
    if (token_count >= 3) {
      return false;
    }
    tokens[token_count] = cursor;
    while (*cursor != '\0' && !isspace((unsigned char)*cursor)) {
      cursor++;
    }
    lengths[token_count] = (size_t)(cursor - tokens[token_count]);
    token_count++;
  }

  if (token_count != 3 || lengths[0] >= sizeof(destination) ||
      lengths[1] >= sizeof(gateway) || lengths[2] == 0 ||
      lengths[2] >= DEV_NAME_LEN) {
    return false;
  }

  memcpy(destination, tokens[0], lengths[0]);
  destination[lengths[0]] = '\0';
  memcpy(gateway, tokens[1], lengths[1]);
  gateway[lengths[1]] = '\0';

  if (strcmp(destination, "default") == 0) {
    destination_block.addr = 0;
    destination_block.prefix = 0;
  } else if (!cidr_parse(destination, &destination_block) ||
             !cidr_is_network(destination_block)) {
    return false;
  }

  if (strcmp(gateway, "direct") == 0) {
    gateway_address = 0;
  } else if (!ip_parse(gateway, &gateway_address)) {
    return false;
  }

  parsed.dest = destination_block;
  parsed.gateway = gateway_address;
  memcpy(parsed.dev, tokens[2], lengths[2]);
  parsed.dev[lengths[2]] = '\0';
  *route = parsed;
  return true;
}

fwd_table_t *table_create(void)
{
  return calloc(1, sizeof(fwd_table_t));
}

void table_destroy(fwd_table_t *table)
{
  if (table != NULL) {
    free(table->routes);
    free(table);
  }
}

size_t table_count(const fwd_table_t *table)
{
  return table == NULL ? 0 : table->count;
}

bool table_add(fwd_table_t *table, const route_t *route)
{
  route_t *grown_routes;
  size_t new_capacity;

  if (table == NULL || route == NULL || route->dest.prefix > 32 ||
      !cidr_is_network(route->dest)) {
    return false;
  }
  for (size_t index = 0; index < table->count; index++) {
    if (table->routes[index].dest.addr == route->dest.addr &&
        table->routes[index].dest.prefix == route->dest.prefix) {
      return false;
    }
  }

  if (table->count == table->capacity) {
    new_capacity = table->capacity == 0 ? 4 : table->capacity * 2;
    if (new_capacity < table->capacity ||
        new_capacity > SIZE_MAX / sizeof(*table->routes)) {
      // GCOVR_EXCL_START
      return false;
      // GCOVR_EXCL_STOP
    }
    grown_routes = realloc(table->routes,
                           new_capacity * sizeof(*table->routes));
    if (grown_routes == NULL) {
      // GCOVR_EXCL_START
      return false;
      // GCOVR_EXCL_STOP
    }
    table->routes = grown_routes;
    table->capacity = new_capacity;
  }

  table->routes[table->count] = *route;
  table->count++;
  return true;
}

bool table_load(fwd_table_t *table, FILE *in, size_t *bad_line)
{
  char *line = NULL;
  size_t line_capacity = 0;
  size_t line_number = 0;
  ssize_t line_length;
  route_t route;
  char *comment;

  if (bad_line != NULL) {
    *bad_line = 0;
  }
  if (table == NULL || in == NULL) {
    return false;
  }

  while ((line_length = getline(&line, &line_capacity, in)) != -1) {
    (void)line_length;
    line_number++;
    comment = strchr(line, '#');
    if (comment != NULL) {
      *comment = '\0';
    }
    comment = line;
    while (*comment != '\0' && isspace((unsigned char)*comment)) {
      comment++;
    }
    if (*comment == '\0') {
      continue;
    }
    if (!route_parse(comment, &route) || !table_add(table, &route)) {
      if (bad_line != NULL) {
        *bad_line = line_number;
      }
      free(line);
      return false;
    }
  }

  free(line);
  if (ferror(in)) {
    return false;
  }
  return true;
}

const route_t *table_lookup(const fwd_table_t *table, uint32_t dest)
{
  const route_t *best = NULL;

  if (table == NULL) {
    return NULL;
  }
  for (size_t index = 0; index < table->count; index++) {
    const route_t *candidate = &table->routes[index];
    if (cidr_contains(candidate->dest, dest) &&
        (best == NULL || candidate->dest.prefix > best->dest.prefix)) {
      best = candidate;
    }
  }
  return best;
}
