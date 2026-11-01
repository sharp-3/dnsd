#ifndef FIELD
#define FIELD(x_type_, x_name_, x_bits_, x_fmt_, ...)
#endif
#ifndef ARRAY
#define ARRAY(x_name_, x_bytes_expr_, x_fmt_fn_)
#endif

#include DEFINE_PACKET_FILE

#undef FIELD
#undef ARRAY
