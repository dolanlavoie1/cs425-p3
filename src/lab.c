#include "lab.h"

#include <stdio.h>

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

  if (out == NULL || !cidr_is_network(block) || n == 0 ||
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
