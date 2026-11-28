#ifndef DNSD_PACKET_CURSOR_H
#define DNSD_PACKET_CURSOR_H

#include <stddef.h>
#include <stdint.h>

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
    return 0 == c->nbits;
}

static inline uint8_t *
cursor_ptr (const cursor_t *c)
{
    return c->buf + c->nbytes;
}

static inline bool
cursor_fits (const cursor_t *c, size_t nbytes, size_t nbits)
{
    if (c->overflow || c->len < c->nbytes) return false;
    size_t avail = c->len - c->nbytes;
    size_t extra = nbits / 8 + (c->nbits + nbits % 8 + 7) / 8;
    return nbytes <= avail && extra <= avail - nbytes;
}

// move
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
