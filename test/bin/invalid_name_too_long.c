#include "dns_test.h"

#define A7 'a', 'a', 'a', 'a', 'a', 'a', 'a'
#define A63 A7, A7, A7, A7, A7, A7, A7, A7, A7

static const uint8_t query[] = {
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 63,
    A63,  63,   A63,  63,   A63,  63,   A63,  0x00, 0x00, 0x01, 0x00, 0x01,
};

static const uint8_t response[] = DNS_TEST_FORMERR_1234;

DNS_TEST_MAIN (query, response)
