#include "lab.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef TEST
#define main main_exclude
#endif

static void print_usage(FILE *out)
{
  fprintf(out,
          "Usage: myapp info <address>/<prefix>\n"
          "       myapp split <network>/<prefix> <count>\n"
          "       myapp lookup <table-file> <address>...\n");
}

static bool parse_count(const char *text, uint32_t *count)
{
  uint64_t value = 0;
  const char *cursor = text;

  if (text == NULL || count == NULL || *text == '\0' ||
      (*text == '0' && text[1] != '\0')) {
    return false;
  }
  while (*cursor != '\0') {
    if (*cursor < '0' || *cursor > '9') {
      return false;
    }
    value = value * 10U + (uint64_t)(*cursor - '0');
    if (value > UINT32_MAX) {
      return false;
    }
    cursor++;
  }
  *count = (uint32_t)value;
  return true;
}

static int command_info(const char *text)
{
  cidr_t block;
  char address[IP_STR_LEN];
  char netmask[IP_STR_LEN];
  char network[IP_STR_LEN];
  char broadcast[IP_STR_LEN];
  char first_host[IP_STR_LEN];
  char last_host[IP_STR_LEN];

  if (!cidr_parse(text, &block)) {
    fprintf(stderr, "myapp: %s: not a valid CIDR block\n", text);
    return 1;
  }

  ip_format(block.addr, address);
  ip_format(cidr_mask(block.prefix), netmask);
  ip_format(cidr_network(block), network);
  ip_format(cidr_broadcast(block), broadcast);
  ip_format(cidr_first_host(block), first_host);
  ip_format(cidr_last_host(block), last_host);
  printf("address    %s\n"
         "prefix     /%u\n"
         "netmask    %s\n"
         "network    %s\n"
         "broadcast  %s\n"
         "first host %s\n"
         "last host  %s\n"
         "hosts      %" PRIu64 "\n",
         address, (unsigned int)(block.prefix > 32 ? 32 : block.prefix),
         netmask, network, broadcast, first_host, last_host,
         cidr_host_count(block));
  return 0;
}

static int command_split(const char *block_text, const char *count_text)
{
  cidr_t block;
  cidr_t subnet;
  uint32_t count;

  if (!cidr_parse(block_text, &block) || !cidr_is_network(block) ||
      !parse_count(count_text, &count) || count == 0 ||
      (count & (count - 1U)) != 0) {
    fprintf(stderr, "myapp: invalid network or subnet count\n");
    return 1;
  }

  for (uint32_t index = 0; index < count; index++) {
    if (!cidr_subnet(block, count, index, &subnet)) {
      fprintf(stderr, "myapp: cannot split network into %u subnets\n", count);
      return 1;
    }
    char formatted[CIDR_STR_LEN];
    cidr_format(subnet, formatted);
    puts(formatted);
  }
  return 0;
}

static int command_lookup(const char *filename, int address_count,
                          char *const addresses[])
{
  FILE *in = fopen(filename, "r");
  fwd_table_t *table;
  size_t bad_line = 0;
  bool malformed = false;
  bool unreachable = false;

  if (in == NULL) {
    fprintf(stderr, "myapp: %s: cannot open table file: %s\n",
            filename, strerror(errno));
    return 2;
  }

  table = table_create();
  if (table == NULL) {
    fclose(in);
    fprintf(stderr, "myapp: could not allocate forwarding table\n");
    return 2;
  }
  if (!table_load(table, in, &bad_line)) {
    fclose(in);
    table_destroy(table);
    if (bad_line != 0) {
      fprintf(stderr, "myapp: %s:%zu: not a valid route\n",
              filename, bad_line);
    } else {
      fprintf(stderr, "myapp: %s: could not read table file\n", filename);
    }
    return 2;
  }
  fclose(in);

  for (int index = 0; index < address_count; index++) {
    uint32_t address;
    char formatted[IP_STR_LEN];
    const route_t *route;

    if (!ip_parse(addresses[index], &address)) {
      fprintf(stderr, "myapp: %s: not a valid address\n", addresses[index]);
      malformed = true;
      continue;
    }
    route = table_lookup(table, address);
    ip_format(address, formatted);
    if (route == NULL) {
      printf("%s unreachable\n", formatted);
      unreachable = true;
    } else if (route->gateway == 0) {
      printf("%s dev %s\n", formatted, route->dev);
    } else {
      char gateway[IP_STR_LEN];
      ip_format(route->gateway, gateway);
      printf("%s via %s dev %s\n", formatted, gateway, route->dev);
    }
  }

  table_destroy(table);
  return malformed ? 1 : (unreachable ? 3 : 0);
}

int main(int argc, char **argv)
{
  if (argc == 1) {
    print_usage(stdout);
    return 0;
  }
  if (argc >= 2 && strcmp(argv[1], "info") == 0 && argc == 3) {
    return command_info(argv[2]);
  }
  if (argc >= 2 && strcmp(argv[1], "split") == 0 && argc == 4) {
    return command_split(argv[2], argv[3]);
  }
  if (argc >= 3 && strcmp(argv[1], "lookup") == 0 && argc >= 4) {
    return command_lookup(argv[2], argc - 3, &argv[3]);
  }

  fprintf(stderr, "myapp: invalid command line\n");
  print_usage(stderr);
  return 1;
}
