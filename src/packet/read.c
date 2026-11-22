#include <assert.h>
#include <string.h>

#include "packet/read.h"

uint64_t
read_bits (const cursor_t *c, size_t nbits)
{
    assert (nbits <= 64);
    if (!cursor_fits_bits (c, nbits)) return 0;

    const uint8_t *p   = cursor_ptr (c);
    size_t         end = cursor_bits (c) + nbits;
    uint64_t       acc = 0;
    size_t         i   = 0;

    for (; (i + 1) * 8 <= end; i++)
        acc = (acc << 8) | p[i];
    if (end % 8) acc = (acc << end % 8) | (p[i] >> (8 - end % 8));

    return nbits == 64 ? acc : acc & ((UINT64_C (1) << nbits) - 1);
}

void
read_bytes (const cursor_t *c, uint8_t *out, size_t nbytes)
{
    assert (cursor_is_aligned (c));
    if (!cursor_fits_bytes (c, nbytes)) memset (out, 0, nbytes);
    else memcpy (out, cursor_ptr (c), nbytes);
}
