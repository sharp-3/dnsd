#ifndef DNSD_PACKET_EMIT_H
#define DNSD_PACKET_EMIT_H

#include <stddef.h>
#include <stdint.h>

#include "packet/cursor.h"

// write_bits, then advances the cursor by nbits. Past the end of buf it writes nothing and
// sets overflow instead (see cursor_t).
void
emit_bits (cursor_t *c, size_t nbits, uint64_t value);

// write_bytes, then advances the cursor by nbytes; sets overflow like emit_bits.
void
emit_bytes (cursor_t *c, const uint8_t *data, size_t nbytes);

#endif
