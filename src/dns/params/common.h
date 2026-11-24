#ifndef DNSD_DNS_PARAMS_COMMON_H
#define DNSD_DNS_PARAMS_COMMON_H

// Shared by the parameter files (class, type, opcode, rcode); not part of the public API.

#include <stddef.h>
#include <stdint.h>

// Whether a and b are equal ignoring ASCII case (locale-independent, unlike strcasecmp).
bool
params_equal (const char *a, const char *b);

// Parses the generic form <prefix><decimal> (RFC 3597, e.g. "TYPE65535"), prefix matched
// ignoring ASCII case, into *out. Only digits may follow the prefix, and the value must be at
// most max. Returns false (leaving *out unchanged) otherwise.
bool
params_generic_from_string (const char *str, const char *prefix, uint32_t max, uint32_t *out);

#endif
