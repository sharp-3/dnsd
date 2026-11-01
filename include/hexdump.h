#ifndef HEXDUMP_H
#define HEXDUMP_H

#include <stddef.h>
#include <stdint.h>

void
hexdump(const uint8_t *buf, size_t buf_len);

#endif // HEXDUMP_H
