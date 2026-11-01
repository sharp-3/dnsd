typedef struct
{
    const uint8_t *packet;
    size_t         packet_bytes;
    // clang-format off
#define FIELD(x_type_, x_name_, x_bits_, x_fmt_, ...)                                              \
    x_type_ x_name_;
#define ARRAY(x_name_, x_bytes_expr_, x_fmt_fn_)                                                   \
    const uint8_t *x_name_;                                                                        \
    size_t         x_name_##_bytes;
#include "_load.h"
    // clang-format on
} PACKET_T;
