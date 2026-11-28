#ifndef DNSD_DNS_ERROR_H
#define DNSD_DNS_ERROR_H

typedef enum
{
    DNS_OK = 0,                  // success
    DNS_OK_NAME_TOO_LONG,        // success, but a name is longer than DNS_NAME_MAX octets
    DNS_ERR_TRUNCATED,           // the data ends before the item does
    DNS_ERR_NAME_BAD_POINTER,    // pointer not to an earlier label start
    DNS_ERR_NAME_RESERVED_LABEL, // label type 0b01 / 0b10
    DNS_ERR_BAD_RDATA,           // RDATA does not fit its TYPE / CLASS
    DNS_ERR_NOMEM,               // memory allocation failed
    DNS_ERR_NAME_LABEL_TOO_LONG, // label longer than 63 octets
    DNS_ERR_BAD_TEXT,            // malformed text form
    DNS_ERR_NAME_COMPRESSED,     // name contains a compression pointer
    DNS_ERR_NO_SPACE,            // output buffer too small
    DNS_ERR_NOT_QUERY,           // QR is set in a message expected to be a query
    DNS_ERR_NOT_IMPLEMENTED,     // OPCODE not supported
    DNS_ERR_BAD_QDCOUNT,         // QDCOUNT not allowed (query: must be 1)
    DNS_ERR_BAD_ANCOUNT,         // ANCOUNT not allowed (query: must be 0)
    DNS_ERR_BAD_NSCOUNT,         // NSCOUNT not allowed (query: must be 0)
    DNS_ERR_BAD_ARCOUNT,         // ARCOUNT not allowed (query: must be 0)
    DNS_ERR_NAME_TOO_LONG,       // name longer than DNS_NAME_MAX octets where that is not allowed
    DNS_ERR_TRAILING_DATA,       // octets left after the last section
    DNS_ERR_NAME_TRUNCATED,      // name data ends within a label
    DNS_ERR_NAME_TRAILING_DATA,  // octets follow the root label of a name
} dns_error_t;

// result
static inline bool
dns_is_ok (dns_error_t err)
{
    switch (err)
    {
    case DNS_OK:
    case DNS_OK_NAME_TOO_LONG:
        return true;
    case DNS_ERR_TRUNCATED:
    case DNS_ERR_NAME_BAD_POINTER:
    case DNS_ERR_NAME_RESERVED_LABEL:
    case DNS_ERR_BAD_RDATA:
    case DNS_ERR_NOMEM:
    case DNS_ERR_NAME_LABEL_TOO_LONG:
    case DNS_ERR_BAD_TEXT:
    case DNS_ERR_NAME_COMPRESSED:
    case DNS_ERR_NO_SPACE:
    case DNS_ERR_NOT_QUERY:
    case DNS_ERR_NOT_IMPLEMENTED:
    case DNS_ERR_BAD_QDCOUNT:
    case DNS_ERR_BAD_ANCOUNT:
    case DNS_ERR_BAD_NSCOUNT:
    case DNS_ERR_BAD_ARCOUNT:
    case DNS_ERR_NAME_TOO_LONG:
    case DNS_ERR_TRAILING_DATA:
    case DNS_ERR_NAME_TRUNCATED:
    case DNS_ERR_NAME_TRAILING_DATA:
        return false;
    }
    return false;
}

static inline dns_error_t
dns_merge_soft (dns_error_t a, dns_error_t b)
{
    if (!dns_is_ok (a)) return a;
    if (!dns_is_ok (b)) return b;
    return DNS_OK != a ? a : b;
}

// dns_error_t --> char * (string)
const char *
dns_error_str (dns_error_t err);

#endif
