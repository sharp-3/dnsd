#ifndef DNSD_PACKET_READ_H
#define DNSD_PACKET_READ_H

#include <stddef.h>
#include <stdint.h>

#include "packet/cursor.h"

// Reads nbits (at most 64) bits at the cursor without moving it; 0 if they are not all
// within buf or the cursor has overflowed.
uint64_t
read_bits (const cursor_t *c, size_t nbits);

// The cursor must be on an octet boundary. out is zeroed if the octets are not all within
// buf or the cursor has overflowed.
void
read_bytes (const cursor_t *c, uint8_t *out, size_t nbytes);

#endif
