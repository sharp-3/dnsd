#ifndef DNSD_DNS_PARAMS_COMMON_H
#define DNSD_DNS_PARAMS_COMMON_H

// Shared by the parameter files (class, type, opcode, rcode); not part of the public API.

#include <stddef.h>
#include <stdint.h>

typedef struct
{
    uint32_t    value;
    const char *name; // mnemonic
} params_name_t;

// One parameter: its mnemonics and its generic form <prefix><decimal> (e.g. "TYPE65535").
typedef struct
{
    const params_name_t *names;
    size_t               count;  // entries in names
    const char          *prefix; // of the generic form
    uint32_t             max;    // largest value the generic form may give
} params_table_t;

#define PARAMS_TABLE(names_, prefix_, max_)                                                        \
    {.names  = (names_),                                                                           \
     .count  = sizeof (names_) / sizeof (names_)[0],                                               \
     .prefix = (prefix_),                                                                          \
     .max    = (max_)}

// params_table_t lookup (value <-- char * (string))
bool
params_from_string (const params_table_t *t, const char *str, uint32_t *out);

// display
const char *
params_display_r (const params_table_t *t, uint32_t value, char *buf, size_t len);

#endif
