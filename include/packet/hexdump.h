#ifndef DNSD_PACKET_HEXDUMP_H
#define DNSD_PACKET_HEXDUMP_H

#include <stddef.h>
#include <stdint.h>

// uint8_t * --> stdout (hex dump)
void
hexdump (const uint8_t *pkt, size_t nbytes_len);

#endif
