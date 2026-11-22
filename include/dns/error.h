#ifndef DNSD_DNS_ERROR_H
#define DNSD_DNS_ERROR_H

typedef enum
{
    DNS_OK = 0,             // success
    DNS_OK_NAME_TOO_LONG,   // success, but a name is longer than DNS_NAME_MAX octets
    DNS_ERR_TRUNCATED,      // the data ends before the item does
    DNS_ERR_BAD_POINTER,    // pointer not to an earlier label start
    DNS_ERR_RESERVED_LABEL, // label type 0b01 / 0b10
    DNS_ERR_BAD_RDATA,      // RDATA does not fit its TYPE / CLASS
    DNS_ERR_NOMEM,          // memory allocation failed
    DNS_ERR_LABEL_TOO_LONG, // label longer than 63 octets
    DNS_ERR_BAD_TEXT,       // malformed text form
    DNS_ERR_COMPRESSED,     // name contains a compression pointer
    DNS_ERR_NO_SPACE,       // output buffer too small
} dns_error_t;

// Whether err means success: the output is filled and the position advanced. DNS_OK_*
// codes add a warning to it. No default, so -Wswitch flags a new code left out here.
static inline bool
dns_is_ok (dns_error_t err)
{
    switch (err)
    {
    case DNS_OK:
    case DNS_OK_NAME_TOO_LONG:
        return true;
    case DNS_ERR_TRUNCATED:
    case DNS_ERR_BAD_POINTER:
    case DNS_ERR_RESERVED_LABEL:
    case DNS_ERR_BAD_RDATA:
    case DNS_ERR_NOMEM:
    case DNS_ERR_LABEL_TOO_LONG:
    case DNS_ERR_BAD_TEXT:
    case DNS_ERR_COMPRESSED:
    case DNS_ERR_NO_SPACE:
        return false;
    }
    return false;
}

// Combines the results of two steps run in order: a hard error in either wins (a first),
// otherwise the first warning (DNS_OK_*), otherwise DNS_OK.
static inline dns_error_t
dns_merge_soft (dns_error_t a, dns_error_t b)
{
    if (!dns_is_ok (a)) return a;
    if (!dns_is_ok (b)) return b;
    return a != DNS_OK ? a : b;
}

const char *
dns_error_str (dns_error_t err);

#endif
