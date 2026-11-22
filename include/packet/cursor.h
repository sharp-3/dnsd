#ifndef DNSD_PACKET_CURSOR_H
#define DNSD_PACKET_CURSOR_H

#include <stddef.h>
#include <stdint.h>

// A packet buffer and a position in it: nbytes whole octets plus nbits (0-7) more bits.
// Change the position only through the functions below so that nbits stays in 0-7 and the
// position never passes the end of buf.
//
// overflow works like the error indicator of a FILE: a move, read or write that would pass
// the end of buf sets it instead, and once it is set every later one does nothing (reads
// give 0). So a run of take / emit calls can be checked once with cursor_is_overflow.
// It is only cleared by assigning a saved cursor back (or cursor_init).
typedef struct
{
    uint8_t *buf;      // the packet being read or written
    size_t   len;      // octets in buf (capacity when writing)
    size_t   nbytes;   // position: whole octets ...
    size_t   nbits;    // ... plus 0-7 bits
    bool     overflow; // a move, read or write went past the end of buf
} cursor_t;

static inline void
cursor_init (cursor_t *c, uint8_t *buf, size_t len)
{
    *c = (cursor_t){.buf = buf, .len = len};
}

static inline size_t
cursor_bytes (const cursor_t *c)
{
    return c->nbytes;
}

static inline size_t
cursor_bits (const cursor_t *c)
{
    return c->nbits;
}

// Whether a move, read or write went past the end of buf (see cursor_t).
static inline bool
cursor_is_overflow (const cursor_t *c)
{
    return c->overflow;
}

// Whether c is on an octet boundary.
static inline bool
cursor_is_aligned (const cursor_t *c)
{
    return c->nbits == 0;
}

// The octet at the position (the one holding the next bit when not aligned).
static inline uint8_t *
cursor_ptr (const cursor_t *c)
{
    return c->buf + c->nbytes;
}

// Whether nbits more bits from the position are within buf. Always false once c has
// overflowed, since nothing more is read or written then.
static inline bool
cursor_fits_bits (const cursor_t *c, size_t nbits)
{
    if (c->overflow || c->nbytes > c->len) return false;
    // Octets touched from the position's octet on: ceil ((c->nbits + nbits) / 8),
    // computed so that it cannot overflow.
    size_t need = nbits / 8 + (c->nbits + nbits % 8 + 7) / 8;
    return need <= c->len - c->nbytes;
}

// Whether nbytes more octets from the position are within buf (false once overflowed).
static inline bool
cursor_fits_bytes (const cursor_t *c, size_t nbytes)
{
    if (c->overflow || c->nbytes > c->len) return false;
    size_t avail = c->len - c->nbytes;
    return c->nbits == 0 ? nbytes <= avail : avail > 0 && nbytes < avail;
}

// Moves nbits bits forward; sets overflow instead if that passes the end of buf.
static inline void
cursor_add_bits (cursor_t *c, size_t nbits)
{
    if (!cursor_fits_bits (c, nbits))
    {
        c->overflow = true;
        return;
    }
    size_t total = c->nbits + nbits % 8;
    c->nbytes += nbits / 8 + (total >> 3);
    c->nbits = total & 0b111;
}

// Moves nbytes octets forward; sets overflow instead if that passes the end of buf.
static inline void
cursor_add_bytes (cursor_t *c, size_t nbytes)
{
    if (!cursor_fits_bytes (c, nbytes))
    {
        c->overflow = true;
        return;
    }
    c->nbytes += nbytes;
}

#endif
