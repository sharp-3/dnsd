#include <assert.h>
#include <string.h>

#include "packet/write.h"

void
write_bits (const cursor_t *c, size_t nbits, uint64_t value)
{
    assert (nbits <= 64);
    if (nbits == 0 || !cursor_fits_bits (c, nbits)) return;

    uint8_t *p    = cursor_ptr (c);
    size_t   head = cursor_bits (c);
    size_t   end  = head + nbits;
    size_t   last = (end - 1) >> 3;
    size_t   tail = (8 - (end & 0b111)) & 0b111;

    for (size_t i = last + 1; i-- > 0;)
    {
        size_t       lo   = i == last ? tail : 0;
        size_t       hi   = i == 0 ? head : 0;
        size_t       n    = 8 - lo - hi;
        unsigned int mask = ((1u << n) - 1) << lo;

        p[i] = (p[i] & ~mask) | ((value << lo) & mask);
        value >>= n;
    }
}

void
write_bytes (const cursor_t *c, const uint8_t *data, size_t nbytes)
{
    assert (cursor_is_aligned (c));
    if (!cursor_fits_bytes (c, nbytes)) return;
    memcpy (cursor_ptr (c), data, nbytes);
}
