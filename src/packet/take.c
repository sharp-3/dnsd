#include "packet/take.h"
#include "packet/read.h"

uint64_t
take_bits (cursor_t *c, size_t nbits)
{
    uint64_t value = read_bits (c, nbits);
    cursor_add_bits (c, nbits);
    return value;
}

void
take_bytes (cursor_t *c, uint8_t *out, size_t nbytes)
{
    read_bytes (c, out, nbytes);
    cursor_add_bytes (c, nbytes);
}
