#include "dns_test.h"

static const uint8_t query[] = {
    0x12,
    0x34,
    0x01,
    0x00,
    0x00,
    0x01,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x07,
    'e',
    'x',
    'a',
};

static const uint8_t response[] = DNS_TEST_FORMERR_1234;

DNS_TEST_MAIN (query, response)
