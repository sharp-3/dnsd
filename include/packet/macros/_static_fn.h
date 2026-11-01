#define FIELD(x_type_, x_name_, x_bits_, x_fmt_, ...)                                              \
    static inline size_t bits_##x_name_(void)                                                      \
    {                                                                                              \
        return (size_t)(x_bits_);                                                                  \
    }                                                                                              \
    static inline void print_##x_name_(x_type_ x_name_)                                            \
    {                                                                                              \
        printf("%s: ", STR(x_name_));                                                              \
        (void)x_name_;                                                                             \
        printf(x_fmt_ __VA_OPT__(, ) __VA_ARGS__);                                                 \
        printf("\n");                                                                              \
    }

#define ARRAY(x_name_, x_bytes_expr_, x_fmt_fn_)                                                   \
    static inline size_t bytes_##x_name_(const PACKET_T *self, const uint8_t *buf, size_t bytes)   \
    {                                                                                              \
        return (size_t)(x_bytes_expr_);                                                            \
    }                                                                                              \
    static inline void print_##x_name_(const uint8_t *buf, size_t bytes)                           \
    {                                                                                              \
        printf("%s: \n", STR(x_name_));                                                            \
        x_fmt_fn_(buf, bytes);                                                                     \
    }

#include "_load.h"

static inline uint64_t
read_bits(const uint8_t *buf, size_t offset, size_t count)
{
    uint64_t value = 0;

    size_t idx = 0;
    while (count != 0)
    {
        idx += offset >> 3;
        offset &= 0x7;

        size_t  lsh  = (8 - offset) > count ? count : (8 - offset);
        size_t  rsh  = 8 - (offset + lsh);
        uint8_t mask = (lsh == 8) ? 0xFF : (1 << lsh) - 1;

        uint8_t tmp = buf[idx];
        tmp         = (tmp >> rsh) & mask;
        value       = (value << lsh) | tmp;

        offset += lsh;
        count -= lsh;
    }

    return value;
}
