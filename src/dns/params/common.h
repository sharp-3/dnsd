#ifndef DNSD_DNS_PARAMS_COMMON_H
#define DNSD_DNS_PARAMS_COMMON_H

#include <stddef.h>
#include <stdint.h>

#include <glib.h>

typedef struct
{
    uint32_t    value;
    const char *name; // mnemonic
} params_name_t;

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

// value --> text (mnemonic, or else the generic form), appended to gs
void
params_to_string (const params_table_t *t, uint32_t value, GString *gs);

#endif
