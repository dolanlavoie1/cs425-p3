#include <stdint.h>

#include "harness/unity.h"
#include "../src/lab.h"

void setUp(void) {}
void tearDown(void) {}

void test_ip_parse_accepts_valid_addresses(void)
{
  uint32_t address = 0;

  TEST_ASSERT_TRUE(ip_parse("192.168.1.10", &address));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xc0a8010a), address);
  TEST_ASSERT_TRUE(ip_parse("0.0.0.0", &address));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0), address);
  TEST_ASSERT_TRUE(ip_parse("255.255.255.255", &address));
  TEST_ASSERT_EQUAL_HEX32(UINT32_MAX, address);
}

void test_ip_parse_rejects_malformed_addresses_and_preserves_output(void)
{
  const char *invalid[] = {
    "1.2.3", "1.2.3.4.5", "1..2.3", "256.1.1.1",
    "010.0.0.1", "1.2.3.4x", "+1.2.3.4", NULL
  };
  uint32_t address = UINT32_C(0x12345678);

  for (size_t index = 0; invalid[index] != NULL; index++) {
    TEST_ASSERT_FALSE(ip_parse(invalid[index], &address));
    TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x12345678), address);
  }
  TEST_ASSERT_FALSE(ip_parse("1.2.3.4", NULL));
}

void test_ip_format(void)
{
  char output[IP_STR_LEN];

  ip_format(UINT32_C(0xc0a8010a), output);
  TEST_ASSERT_EQUAL_STRING("192.168.1.10", output);
  ip_format(UINT32_MAX, output);
  TEST_ASSERT_EQUAL_STRING("255.255.255.255", output);
}

void test_cidr_parse_accepts_valid_blocks(void)
{
  cidr_t block = {0};

  TEST_ASSERT_TRUE(cidr_parse("132.178.227.11/25", &block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x84b2e30b), block.addr);
  TEST_ASSERT_EQUAL_UINT8(25, block.prefix);
  TEST_ASSERT_TRUE(cidr_parse("0.0.0.0/0", &block));
  TEST_ASSERT_EQUAL_UINT8(0, block.prefix);
  TEST_ASSERT_TRUE(cidr_parse("255.255.255.255/32", &block));
  TEST_ASSERT_EQUAL_UINT8(32, block.prefix);
}

void test_cidr_parse_rejects_malformed_blocks_and_preserves_output(void)
{
  const char *invalid[] = {
    "1.2.3.4/33", "1.2.3.4/024", "1.2.3.4/",
    "1.2.3/24", "1.2.3.4/24x", "1.2.3.4/ 24", NULL
  };
  cidr_t block = {UINT32_C(0x12345678), 9};

  for (size_t index = 0; invalid[index] != NULL; index++) {
    TEST_ASSERT_FALSE(cidr_parse(invalid[index], &block));
    TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x12345678), block.addr);
    TEST_ASSERT_EQUAL_UINT8(9, block.prefix);
  }
  TEST_ASSERT_FALSE(cidr_parse(NULL, &block));
  TEST_ASSERT_FALSE(cidr_parse("1.2.3.4/24", NULL));
}

void test_cidr_format(void)
{
  char output[CIDR_STR_LEN];

  cidr_format((cidr_t){UINT32_C(0x84b2e30b), 25}, output);
  TEST_ASSERT_EQUAL_STRING("132.178.227.11/25", output);
  cidr_format((cidr_t){UINT32_MAX, 255}, output);
  TEST_ASSERT_EQUAL_STRING("255.255.255.255/32", output);
}

void test_cidr_mask_and_block_boundaries(void)
{
  cidr_t block = {UINT32_C(0x84b2e30b), 25};

  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0), cidr_mask(0));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xffffff80), cidr_mask(25));
  TEST_ASSERT_EQUAL_HEX32(UINT32_MAX, cidr_mask(32));
  TEST_ASSERT_EQUAL_HEX32(UINT32_MAX, cidr_mask(33));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x84b2e300), cidr_network(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x84b2e37f), cidr_broadcast(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x84b2e301), cidr_first_host(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x84b2e37e), cidr_last_host(block));
  TEST_ASSERT_EQUAL_UINT64(126, cidr_host_count(block));
}

void test_cidr_special_host_ranges(void)
{
  cidr_t block31 = {UINT32_C(0x0a000002), 31};
  cidr_t block32 = {UINT32_C(0xc0a8010a), 32};
  cidr_t block0 = {UINT32_C(0x12345678), 0};

  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x0a000002), cidr_network(block31));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x0a000003), cidr_broadcast(block31));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x0a000002), cidr_first_host(block31));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x0a000003), cidr_last_host(block31));
  TEST_ASSERT_EQUAL_UINT64(2, cidr_host_count(block31));

  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xc0a8010a), cidr_network(block32));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xc0a8010a), cidr_broadcast(block32));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xc0a8010a), cidr_first_host(block32));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xc0a8010a), cidr_last_host(block32));
  TEST_ASSERT_EQUAL_UINT64(1, cidr_host_count(block32));

  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0), cidr_network(block0));
  TEST_ASSERT_EQUAL_HEX32(UINT32_MAX, cidr_broadcast(block0));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(1), cidr_first_host(block0));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xfffffffe), cidr_last_host(block0));
  TEST_ASSERT_EQUAL_UINT64(UINT64_C(4294967294), cidr_host_count(block0));
}

void test_cidr_contains_and_network_check(void)
{
  cidr_t network = {UINT32_C(0xc0a80100), 24};
  cidr_t host = {UINT32_C(0xc0a80101), 24};

  TEST_ASSERT_TRUE(cidr_contains(network, UINT32_C(0xc0a801fe)));
  TEST_ASSERT_FALSE(cidr_contains(network, UINT32_C(0xc0a80200)));
  TEST_ASSERT_TRUE(cidr_is_network(network));
  TEST_ASSERT_FALSE(cidr_is_network(host));
}

void test_cidr_subnet(void)
{
  cidr_t block = {UINT32_C(0xc0a80100), 24};
  cidr_t zero_block = {0, 0};
  cidr_t subnet = {0};

  TEST_ASSERT_TRUE(cidr_subnet(block, 4, 0, &subnet));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xc0a80100), subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(26, subnet.prefix);
  TEST_ASSERT_TRUE(cidr_subnet(block, 4, 3, &subnet));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xc0a801c0), subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(26, subnet.prefix);
  TEST_ASSERT_TRUE(cidr_subnet(block, 1, 0, &subnet));
  TEST_ASSERT_EQUAL_HEX32(block.addr, subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(block.prefix, subnet.prefix);
  TEST_ASSERT_TRUE(cidr_subnet(zero_block, 1, 0, &subnet));
  TEST_ASSERT_EQUAL_HEX32(0, subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(0, subnet.prefix);
}

void test_cidr_subnet_rejects_invalid_requests_and_preserves_output(void)
{
  cidr_t output = {UINT32_C(0x12345678), 9};
  cidr_t non_network = {UINT32_C(0xc0a80101), 24};
  cidr_t narrow = {UINT32_C(0xffffffff), 32};

  TEST_ASSERT_FALSE(cidr_subnet(non_network, 2, 0, &output));
  TEST_ASSERT_FALSE(cidr_subnet((cidr_t){0, 0}, 3, 0, &output));
  TEST_ASSERT_FALSE(cidr_subnet((cidr_t){0, 0}, 2, 2, &output));
  TEST_ASSERT_FALSE(cidr_subnet(narrow, 2, 0, &output));
  TEST_ASSERT_FALSE(cidr_subnet((cidr_t){0, 0}, 1, 0, NULL));
  TEST_ASSERT_FALSE(cidr_subnet((cidr_t){0, 0}, 0, 0, &output));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x12345678), output.addr);
  TEST_ASSERT_EQUAL_UINT8(9, output.prefix);
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_ip_parse_accepts_valid_addresses);
  RUN_TEST(test_ip_parse_rejects_malformed_addresses_and_preserves_output);
  RUN_TEST(test_ip_format);
  RUN_TEST(test_cidr_parse_accepts_valid_blocks);
  RUN_TEST(test_cidr_parse_rejects_malformed_blocks_and_preserves_output);
  RUN_TEST(test_cidr_format);
  RUN_TEST(test_cidr_mask_and_block_boundaries);
  RUN_TEST(test_cidr_special_host_ranges);
  RUN_TEST(test_cidr_contains_and_network_check);
  RUN_TEST(test_cidr_subnet);
  RUN_TEST(test_cidr_subnet_rejects_invalid_requests_and_preserves_output);
  return UNITY_END();
}
