#ifndef DNSD_PACKET_WRITE_H
#define DNSD_PACKET_WRITE_H

#include <stddef.h>
#include <stdint.h>

#include "packet/cursor.h"

// Writes the low nbits (at most 64) bits of value at the cursor without moving it; does
// nothing if they are not all within buf or the cursor has overflowed.
void
write_bits (const cursor_t *c, size_t nbits, uint64_t value);

// The cursor must be on an octet boundary. Does nothing if the octets are not all within
// buf or the cursor has overflowed.
void
write_bytes (const cursor_t *c, const uint8_t *data, size_t nbytes);

#endif
