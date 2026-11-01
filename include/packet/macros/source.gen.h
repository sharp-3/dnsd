#include <assert.h>
#include <stdio.h>

#include "_define.h"
#include "_static_fn.h"

const uint8_t *
PACKET_T_SER(const PACKET_T *self)
{
    return nullptr;
}

PACKET_T
PACKET_T_DE(const uint8_t *packet, size_t packet_bytes, int *result)
{
    PACKET_T self = {packet, packet_bytes};
    *result       = 0;

    struct
    {
        size_t nbytes;
        size_t nbits;
    } offset = {0};

#define FIELD(x_type_, x_name_, x_bits_, x_fmt_, ...)                                              \
    {                                                                                              \
        size_t nbits = bits_##x_name_();                                                           \
        if (packet_bytes - offset.nbytes < ((nbits + 7) >> 3)) return self;                        \
        self.x_name_ = (x_type_)read_bits(&packet[offset.nbytes], offset.nbits, nbits);            \
        offset.nbits += nbits;                                                                     \
        offset.nbytes += offset.nbits >> 3;                                                        \
        offset.nbits &= 0x07;                                                                      \
        result += 1;                                                                               \
    }
#define ARRAY(x_name_, x_bytes_expr_, x_fmt_fn_)                                                   \
    {                                                                                              \
        assert(offset.nbits == 0);                                                                 \
        size_t nbytes =                                                                            \
            bytes_##x_name_(&self, &packet[offset.nbytes], packet_bytes - offset.nbytes);          \
        if (packet_bytes - offset.nbytes < nbytes || nbytes == SIZE_MAX) return self;              \
        self.x_name_         = &packet[offset.nbytes];                                             \
        self.x_name_##_bytes = nbytes;                                                             \
        offset.nbytes += nbytes;                                                                   \
        result += 1;                                                                               \
    }
#include "_load.h"

    assert(offset.nbits == 0);
    if (offset.nbytes != packet_bytes) return self;

    *result = 0;
    return self;
}

void
PACKET_T_PRINT(const PACKET_T *self)
{
#define FIELD(x_type_, x_name_, x_bits_, x_fmt_, ...)                                              \
    {                                                                                              \
        print_##x_name_(self->x_name_);                                                            \
    }
#define ARRAY(x_name_, x_bytes_expr_, x_fmt_fn_)                                                   \
    {                                                                                              \
        print_##x_name_(self->x_name_, self->x_name_##_bytes);                                     \
    }

#include "_load.h"
}

#include "_undef.h"
