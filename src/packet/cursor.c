#include <assert.h>
#include <string.h>

#include "packet/cursor.h"

#define OCTET_BITS 8

// The field is bits offset..end-1 counted from the high bit of the position's octet. In octet
// i it takes bits start..last (from the high bit), leaving tail low bits: bits many, at mask.

// First bit of octet i the field takes.
static inline size_t
start_bits (size_t i, size_t offset)
{
    return i == 0 ? offset : 0;
}

// Last bit of octet i the field takes.
static inline size_t
last_bits (size_t i, size_t end)
{
    return ((i + 1) * OCTET_BITS <= end ? OCTET_BITS : end - i * OCTET_BITS) - 1;
}

uint64_t
read_bits (const cursor_t *c, size_t nbits)
{
    assert (nbits <= 64);
    if (nbits == 0 || !cursor_fits (c, 0, nbits)) return 0;

    const uint8_t *p      = cursor_ptr (c);
    size_t         offset = cursor_bits (c);
    size_t         end    = offset + nbits;
    uint64_t       acc    = 0;

    // From the first octet on, each adding its bits below the ones before.
    for (size_t i = 0; i * OCTET_BITS < end; i++)
    {
        size_t       start = start_bits (i, offset);
        size_t       last  = last_bits (i, end);
        size_t       tail  = OCTET_BITS - 1 - last;
        size_t       bits  = last - start + 1;
        unsigned int mask  = ((1u << bits) - 1) << tail;

        acc = (acc << bits) | ((p[i] & mask) >> tail);
    }
    return acc;
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

    uint8_t *p      = cursor_ptr (c);
    size_t   offset = cursor_bits (c);
    size_t   end    = offset + nbits;

    // From the last octet back, each taking the low bits of value left.
    for (size_t i = (end + OCTET_BITS - 1) / OCTET_BITS; 0 < i--;)
    {
        size_t       start = start_bits (i, offset);
        size_t       last  = last_bits (i, end);
        size_t       tail  = OCTET_BITS - 1 - last;
        size_t       bits  = last - start + 1;
        unsigned int mask  = ((1u << bits) - 1) << tail;

        p[i] = (p[i] & ~mask) | ((value << tail) & mask);
        value >>= bits;
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
