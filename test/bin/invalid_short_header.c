#include "dns_test.h"

static const uint8_t query[] = {
    0x12,
    0x34,
    0x01,
    0x00,
    0x00,
};

DNS_TEST_MAIN_NO_REPLY (query)
