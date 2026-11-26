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

// init
static inline void
cursor_init (cursor_t *c, uint8_t *buf, size_t len)
{
    *c = (cursor_t){.buf = buf, .len = len};
}

// position / state
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

static inline bool
cursor_is_overflow (const cursor_t *c)
{
    return c->overflow;
}

static inline bool
cursor_is_aligned (const cursor_t *c)
{
    return c->nbits == 0;
}

static inline uint8_t *
cursor_ptr (const cursor_t *c)
{
    return c->buf + c->nbytes;
}

// Whether nbytes octets plus nbits bits from the position are within buf.
static inline bool
cursor_fits (const cursor_t *c, size_t nbytes, size_t nbits)
{
    if (c->overflow || c->nbytes > c->len) return false;
    // Octets touched from the position's octet on: nbytes + ceil ((c->nbits + nbits) / 8),
    // computed so that it cannot overflow.
    size_t avail = c->len - c->nbytes;
    size_t extra = nbits / 8 + (c->nbits + nbits % 8 + 7) / 8;
    return nbytes <= avail && extra <= avail - nbytes;
}

// move by nbytes octets plus nbits bits
static inline void
cursor_add (cursor_t *c, size_t nbytes, size_t nbits)
{
    if (!cursor_fits (c, nbytes, nbits))
    {
        c->overflow = true;
        return;
    }
    size_t total = c->nbits + nbits % 8;
    c->nbytes += nbytes + nbits / 8 + (total >> 3);
    c->nbits = total & 0b111;
}

// read / write (without moving)
uint64_t
read_bits (const cursor_t *c, size_t nbits);
void
read_bytes (const cursor_t *c, uint8_t *out, size_t nbytes);
void
write_bits (const cursor_t *c, size_t nbits, uint64_t value);
void
write_bytes (const cursor_t *c, const uint8_t *data, size_t nbytes);

// take / emit (read / write, then move)
uint64_t
take_bits (cursor_t *c, size_t nbits);
void
take_bytes (cursor_t *c, uint8_t *out, size_t nbytes);
void
emit_bits (cursor_t *c, size_t nbits, uint64_t value);
void
emit_bytes (cursor_t *c, const uint8_t *data, size_t nbytes);

#endif
