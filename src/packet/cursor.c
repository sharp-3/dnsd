#include <assert.h>
#include <string.h>

#include "packet/cursor.h"

uint64_t
read_bits (const cursor_t *c, size_t nbits)
{
    assert (nbits <= 64);
    if (!cursor_fits (c, 0, nbits)) return 0;

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
    if (!cursor_fits (c, nbytes, 0)) memset (out, 0, nbytes);
    else memcpy (out, cursor_ptr (c), nbytes);
}

void
write_bits (const cursor_t *c, size_t nbits, uint64_t value)
{
    assert (nbits <= 64);
    if (nbits == 0 || !cursor_fits (c, 0, nbits)) return;

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
    if (!cursor_fits (c, nbytes, 0)) return;
    memcpy (cursor_ptr (c), data, nbytes);
}

uint64_t
take_bits (cursor_t *c, size_t nbits)
{
    uint64_t value = read_bits (c, nbits);
    cursor_add (c, 0, nbits);
    return value;
}

void
take_bytes (cursor_t *c, uint8_t *out, size_t nbytes)
{
    read_bytes (c, out, nbytes);
    cursor_add (c, nbytes, 0);
}

void
emit_bits (cursor_t *c, size_t nbits, uint64_t value)
{
    write_bits (c, nbits, value);
    cursor_add (c, 0, nbits);
}

void
emit_bytes (cursor_t *c, const uint8_t *data, size_t nbytes)
{
    write_bytes (c, data, nbytes);
    cursor_add (c, nbytes, 0);
}
