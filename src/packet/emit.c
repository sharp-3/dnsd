#include "packet/emit.h"
#include "packet/write.h"

void
emit_bits (cursor_t *c, size_t nbits, uint64_t value)
{
    write_bits (c, nbits, value);
    cursor_add_bits (c, nbits);
}

void
emit_bytes (cursor_t *c, const uint8_t *data, size_t nbytes)
{
    write_bytes (c, data, nbytes);
    cursor_add_bytes (c, nbytes);
}
