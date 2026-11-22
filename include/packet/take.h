#ifndef DNSD_PACKET_TAKE_H
#define DNSD_PACKET_TAKE_H

#include <stddef.h>
#include <stdint.h>

#include "packet/cursor.h"

// read_bits, then advances the cursor by nbits. Past the end of buf it returns 0 and sets
// overflow instead (see cursor_t).
uint64_t
take_bits (cursor_t *c, size_t nbits);

// read_bytes, then advances the cursor by nbytes; sets overflow like take_bits.
void
take_bytes (cursor_t *c, uint8_t *out, size_t nbytes);

#endif
