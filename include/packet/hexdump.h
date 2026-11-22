#ifndef DNSD_PACKET_HEXDUMP_H
#define DNSD_PACKET_HEXDUMP_H

#include <stddef.h>
#include <stdint.h>

void
hexdump (const uint8_t *pkt, size_t nbytes_len);

#endif
