#include <stddef.h>
#include <stdint.h>

#include "_define.h"
#include "_struct.h"

const uint8_t *
PACKET_T_SER(const PACKET_T *self);

PACKET_T
PACKET_T_DE(const uint8_t *packet, size_t bytes, int *result);

void
PACKET_T_PRINT(const PACKET_T *self);

#include "_undef.h"
