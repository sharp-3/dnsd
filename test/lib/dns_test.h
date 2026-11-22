#ifndef DNSD_TEST_DNS_TEST_H
#define DNSD_TEST_DNS_TEST_H

#include <stddef.h>
#include <stdint.h>

int
dns_test_run (int            argc,
              char         **argv,
              const uint8_t *query,
              size_t         query_len,
              const uint8_t *response,
              size_t         response_len);

#define DNS_TEST_MAIN(query, response)                                                             \
    int main (int argc, char **argv)                                                               \
    {                                                                                              \
        return dns_test_run (argc, argv, (query), sizeof (query), (response), sizeof (response));  \
    }

#define DNS_TEST_MAIN_NO_REPLY(query)                                                              \
    int main (int argc, char **argv)                                                               \
    {                                                                                              \
        return dns_test_run (argc, argv, (query), sizeof (query), NULL, 0);                        \
    }

#define DNS_TEST_FORMERR_1234                                                                      \
    {0x12, 0x34, 0x81, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

#endif
