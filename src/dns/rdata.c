#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <stdarg.h>
#include <stdio.h>

#include "dns/name.h"
#include "dns/rdata.h"
#include "packet/emit.h"
#include "packet/take.h"

bool
dns_rdata_known (dns_type_t type, dns_class_t class)
{
    switch (type)
    {
    case DNS_TYPE_A:
    case DNS_TYPE_AAAA:
        return class == DNS_CLASS_IN;
    case DNS_TYPE_NS:
    case DNS_TYPE_CNAME:
    case DNS_TYPE_PTR:
    case DNS_TYPE_DNAME:
    case DNS_TYPE_MX:
    case DNS_TYPE_SRV:
    case DNS_TYPE_SOA:
    case DNS_TYPE_TXT:
        return true;
    default:
        return false;
    }
}

// Limits p->cur to the len octets of RDATA at it, so that reading past them overflows (or
// truncates a name). Saves the cursor in *start for rdata_end.
static dns_error_t
rdata_begin (dns_parser_t *p, size_t len, cursor_t *start)
{
    if (!cursor_fits_bytes (&p->cur, len)) return DNS_ERR_TRUNCATED;
    *start     = p->cur;
    p->cur.len = cursor_bytes (&p->cur) + len;
    return DNS_OK;
}

// Ends what rdata_begin started, given the result err of reading the RDATA. Not reading it
// exactly (too much or too little) is DNS_ERR_BAD_RDATA. On success p->cur stays after the
// RDATA; on error it goes back to *start.
static dns_error_t
rdata_end (dns_parser_t *p, const cursor_t *start, dns_error_t err)
{
    bool whole = !cursor_is_overflow (&p->cur) && cursor_bytes (&p->cur) == p->cur.len;
    if (err == DNS_ERR_TRUNCATED || (dns_is_ok (err) && !whole)) err = DNS_ERR_BAD_RDATA;

    if (dns_is_ok (err)) p->cur.len = start->len;
    else p->cur = *start;
    return err;
}

dns_error_t
dns_rdata_a_from_bytes (dns_parser_t *p, size_t len, dns_rdata_a_t *out)
{
    cursor_t    start;
    dns_error_t err = rdata_begin (p, len, &start);
    if (err != DNS_OK) return err;

    dns_rdata_a_t rd;
    take_bytes (&p->cur, rd.addr, sizeof rd.addr);
    err = rdata_end (p, &start, DNS_OK);
    if (dns_is_ok (err)) *out = rd;
    return err;
}

dns_error_t
dns_rdata_aaaa_from_bytes (dns_parser_t *p, size_t len, dns_rdata_aaaa_t *out)
{
    cursor_t    start;
    dns_error_t err = rdata_begin (p, len, &start);
    if (err != DNS_OK) return err;

    dns_rdata_aaaa_t rd;
    take_bytes (&p->cur, rd.addr, sizeof rd.addr);
    err = rdata_end (p, &start, DNS_OK);
    if (dns_is_ok (err)) *out = rd;
    return err;
}

// A single domain name filling the whole RDATA (NS, CNAME, PTR, DNAME).
static dns_error_t
name_from_bytes (dns_parser_t *p, size_t len, dns_name_t *out)
{
    cursor_t    start;
    dns_error_t err = rdata_begin (p, len, &start);
    if (err != DNS_OK) return err;

    dns_name_t name;
    err = rdata_end (p, &start, dns_name_from_bytes (p, &name));
    if (dns_is_ok (err)) *out = name;
    return err;
}

dns_error_t
dns_rdata_ns_from_bytes (dns_parser_t *p, size_t len, dns_rdata_ns_t *out)
{
    return name_from_bytes (p, len, &out->nsdname);
}

dns_error_t
dns_rdata_cname_from_bytes (dns_parser_t *p, size_t len, dns_rdata_cname_t *out)
{
    return name_from_bytes (p, len, &out->cname);
}

dns_error_t
dns_rdata_ptr_from_bytes (dns_parser_t *p, size_t len, dns_rdata_ptr_t *out)
{
    return name_from_bytes (p, len, &out->ptrdname);
}

dns_error_t
dns_rdata_dname_from_bytes (dns_parser_t *p, size_t len, dns_rdata_dname_t *out)
{
    return name_from_bytes (p, len, &out->target);
}

dns_error_t
dns_rdata_mx_from_bytes (dns_parser_t *p, size_t len, dns_rdata_mx_t *out)
{
    cursor_t    start;
    dns_error_t err = rdata_begin (p, len, &start);
    if (err != DNS_OK) return err;

    dns_rdata_mx_t rd;
    rd.preference = take_bits (&p->cur, 16);
    err           = rdata_end (p, &start, dns_name_from_bytes (p, &rd.exchange));
    if (dns_is_ok (err)) *out = rd;
    return err;
}

dns_error_t
dns_rdata_srv_from_bytes (dns_parser_t *p, size_t len, dns_rdata_srv_t *out)
{
    cursor_t    start;
    dns_error_t err = rdata_begin (p, len, &start);
    if (err != DNS_OK) return err;

    dns_rdata_srv_t rd;
    rd.priority = take_bits (&p->cur, 16);
    rd.weight   = take_bits (&p->cur, 16);
    rd.port     = take_bits (&p->cur, 16);
    err         = rdata_end (p, &start, dns_name_from_bytes (p, &rd.target));
    if (dns_is_ok (err)) *out = rd;
    return err;
}

dns_error_t
dns_rdata_soa_from_bytes (dns_parser_t *p, size_t len, dns_rdata_soa_t *out)
{
    cursor_t    start;
    dns_error_t err = rdata_begin (p, len, &start);
    if (err != DNS_OK) return err;

    dns_rdata_soa_t rd;
    err = dns_name_from_bytes (p, &rd.mname);
    if (dns_is_ok (err)) err = dns_merge_soft (err, dns_name_from_bytes (p, &rd.rname));
    rd.serial  = take_bits (&p->cur, 32);
    rd.refresh = take_bits (&p->cur, 32);
    rd.retry   = take_bits (&p->cur, 32);
    rd.expire  = take_bits (&p->cur, 32);
    rd.minimum = take_bits (&p->cur, 32);
    err        = rdata_end (p, &start, err);
    if (dns_is_ok (err)) *out = rd;
    return err;
}

dns_error_t
dns_rdata_txt_from_bytes (dns_parser_t *p, size_t len, dns_rdata_txt_t *out)
{
    cursor_t    start;
    dns_error_t err = rdata_begin (p, len, &start);
    if (err != DNS_OK) return err;

    dns_rdata_txt_t rd;
    // One or more <character-string>s (length octet + octets); a length running past the
    // RDATA overflows.
    rd.data = cursor_ptr (&p->cur);
    rd.len  = len;
    if (len == 0) err = DNS_ERR_BAD_RDATA;
    while (!cursor_is_overflow (&p->cur) && cursor_bytes (&p->cur) < p->cur.len)
        cursor_add_bytes (&p->cur, take_bits (&p->cur, 8));
    err = rdata_end (p, &start, err);
    if (dns_is_ok (err)) *out = rd;
    return err;
}

dns_error_t
dns_rdata_unknown_from_bytes (dns_parser_t *p, size_t len, dns_rdata_unknown_t *out)
{
    cursor_t    start;
    dns_error_t err = rdata_begin (p, len, &start);
    if (err != DNS_OK) return err;

    dns_rdata_unknown_t rd;
    rd.data = cursor_ptr (&p->cur);
    rd.len  = len;
    cursor_add_bytes (&p->cur, len);
    err = rdata_end (p, &start, DNS_OK);
    if (dns_is_ok (err)) *out = rd;
    return err;
}

dns_error_t
dns_rdata_from_bytes (
    dns_parser_t *p, dns_type_t type, dns_class_t class, size_t len, dns_rdata_t *out)
{
    if (!dns_rdata_known (type, class)) return dns_rdata_unknown_from_bytes (p, len, &out->unknown);

    switch (type)
    {
    case DNS_TYPE_A:
        return dns_rdata_a_from_bytes (p, len, &out->a);
    case DNS_TYPE_AAAA:
        return dns_rdata_aaaa_from_bytes (p, len, &out->aaaa);
    case DNS_TYPE_NS:
        return dns_rdata_ns_from_bytes (p, len, &out->ns);
    case DNS_TYPE_CNAME:
        return dns_rdata_cname_from_bytes (p, len, &out->cname);
    case DNS_TYPE_PTR:
        return dns_rdata_ptr_from_bytes (p, len, &out->ptr);
    case DNS_TYPE_DNAME:
        return dns_rdata_dname_from_bytes (p, len, &out->dname);
    case DNS_TYPE_MX:
        return dns_rdata_mx_from_bytes (p, len, &out->mx);
    case DNS_TYPE_SRV:
        return dns_rdata_srv_from_bytes (p, len, &out->srv);
    case DNS_TYPE_SOA:
        return dns_rdata_soa_from_bytes (p, len, &out->soa);
    case DNS_TYPE_TXT:
        return dns_rdata_txt_from_bytes (p, len, &out->txt);
    default:
        return dns_rdata_unknown_from_bytes (p, len, &out->unknown);
    }
}

size_t
dns_rdata_length (dns_type_t type, dns_class_t class, const dns_rdata_t *rd)
{
    if (!dns_rdata_known (type, class)) return rd->unknown.len;

    switch (type)
    {
    case DNS_TYPE_A:
        return sizeof rd->a.addr;
    case DNS_TYPE_AAAA:
        return sizeof rd->aaaa.addr;
    case DNS_TYPE_NS:
        return rd->ns.nsdname.len;
    case DNS_TYPE_CNAME:
        return rd->cname.cname.len;
    case DNS_TYPE_PTR:
        return rd->ptr.ptrdname.len;
    case DNS_TYPE_DNAME:
        return rd->dname.target.len;
    case DNS_TYPE_MX:
        return 2 + rd->mx.exchange.len;
    case DNS_TYPE_SRV:
        return 6 + rd->srv.target.len;
    case DNS_TYPE_SOA:
        return rd->soa.mname.len + rd->soa.rname.len + 20;
    case DNS_TYPE_TXT:
        return rd->txt.len;
    default:
        return rd->unknown.len;
    }
}

// Ends a write of RDATA that started at *start: if it did not fit (or p->cur had already
// overflowed), p->cur goes back to *start and the result is DNS_ERR_NO_SPACE.
static dns_error_t
put_end (dns_parser_t *p, const cursor_t *start)
{
    if (!cursor_is_overflow (&p->cur)) return DNS_OK;
    p->cur = *start;
    return DNS_ERR_NO_SPACE;
}

dns_error_t
dns_rdata_a_to_bytes (dns_parser_t *p, const dns_rdata_a_t *rd)
{
    cursor_t start = p->cur;
    emit_bytes (&p->cur, rd->addr, sizeof rd->addr);
    return put_end (p, &start);
}

dns_error_t
dns_rdata_aaaa_to_bytes (dns_parser_t *p, const dns_rdata_aaaa_t *rd)
{
    cursor_t start = p->cur;
    emit_bytes (&p->cur, rd->addr, sizeof rd->addr);
    return put_end (p, &start);
}

// A single domain name filling the whole RDATA (NS, CNAME, PTR, DNAME).
static dns_error_t
name_to_bytes (dns_parser_t *p, const dns_name_t *name)
{
    cursor_t start = p->cur;
    emit_bytes (&p->cur, name->ptr, name->len);
    return put_end (p, &start);
}

dns_error_t
dns_rdata_ns_to_bytes (dns_parser_t *p, const dns_rdata_ns_t *rd)
{
    return name_to_bytes (p, &rd->nsdname);
}

dns_error_t
dns_rdata_cname_to_bytes (dns_parser_t *p, const dns_rdata_cname_t *rd)
{
    return name_to_bytes (p, &rd->cname);
}

dns_error_t
dns_rdata_ptr_to_bytes (dns_parser_t *p, const dns_rdata_ptr_t *rd)
{
    return name_to_bytes (p, &rd->ptrdname);
}

dns_error_t
dns_rdata_dname_to_bytes (dns_parser_t *p, const dns_rdata_dname_t *rd)
{
    return name_to_bytes (p, &rd->target);
}

dns_error_t
dns_rdata_mx_to_bytes (dns_parser_t *p, const dns_rdata_mx_t *rd)
{
    cursor_t start = p->cur;
    emit_bits (&p->cur, 16, rd->preference);
    emit_bytes (&p->cur, rd->exchange.ptr, rd->exchange.len);
    return put_end (p, &start);
}

dns_error_t
dns_rdata_srv_to_bytes (dns_parser_t *p, const dns_rdata_srv_t *rd)
{
    cursor_t start = p->cur;
    emit_bits (&p->cur, 16, rd->priority);
    emit_bits (&p->cur, 16, rd->weight);
    emit_bits (&p->cur, 16, rd->port);
    emit_bytes (&p->cur, rd->target.ptr, rd->target.len);
    return put_end (p, &start);
}

dns_error_t
dns_rdata_soa_to_bytes (dns_parser_t *p, const dns_rdata_soa_t *rd)
{
    cursor_t start = p->cur;
    emit_bytes (&p->cur, rd->mname.ptr, rd->mname.len);
    emit_bytes (&p->cur, rd->rname.ptr, rd->rname.len);
    emit_bits (&p->cur, 32, rd->serial);
    emit_bits (&p->cur, 32, rd->refresh);
    emit_bits (&p->cur, 32, rd->retry);
    emit_bits (&p->cur, 32, rd->expire);
    emit_bits (&p->cur, 32, rd->minimum);
    return put_end (p, &start);
}

dns_error_t
dns_rdata_txt_to_bytes (dns_parser_t *p, const dns_rdata_txt_t *rd)
{
    cursor_t start = p->cur;
    emit_bytes (&p->cur, rd->data, rd->len);
    return put_end (p, &start);
}

dns_error_t
dns_rdata_unknown_to_bytes (dns_parser_t *p, const dns_rdata_unknown_t *rd)
{
    cursor_t start = p->cur;
    emit_bytes (&p->cur, rd->data, rd->len);
    return put_end (p, &start);
}

dns_error_t
dns_rdata_to_bytes (dns_parser_t *p, dns_type_t type, dns_class_t class, const dns_rdata_t *rd)
{
    if (!dns_rdata_known (type, class)) return dns_rdata_unknown_to_bytes (p, &rd->unknown);

    switch (type)
    {
    case DNS_TYPE_A:
        return dns_rdata_a_to_bytes (p, &rd->a);
    case DNS_TYPE_AAAA:
        return dns_rdata_aaaa_to_bytes (p, &rd->aaaa);
    case DNS_TYPE_NS:
        return dns_rdata_ns_to_bytes (p, &rd->ns);
    case DNS_TYPE_CNAME:
        return dns_rdata_cname_to_bytes (p, &rd->cname);
    case DNS_TYPE_PTR:
        return dns_rdata_ptr_to_bytes (p, &rd->ptr);
    case DNS_TYPE_DNAME:
        return dns_rdata_dname_to_bytes (p, &rd->dname);
    case DNS_TYPE_MX:
        return dns_rdata_mx_to_bytes (p, &rd->mx);
    case DNS_TYPE_SRV:
        return dns_rdata_srv_to_bytes (p, &rd->srv);
    case DNS_TYPE_SOA:
        return dns_rdata_soa_to_bytes (p, &rd->soa);
    case DNS_TYPE_TXT:
        return dns_rdata_txt_to_bytes (p, &rd->txt);
    default:
        return dns_rdata_unknown_to_bytes (p, &rd->unknown);
    }
}

static void
appendf (char *buf, size_t len, size_t *out, const char *fmt, ...)
{
    if (*out >= len) return;

    va_list ap;
    va_start (ap, fmt);
    int n = vsnprintf (buf + *out, len - *out, fmt, ap);
    va_end (ap);

    if (n < 0 || (size_t)n >= len - *out) *out = len;
    else *out += n;
}

static void
append_string (char *buf, size_t len, size_t *out, const uint8_t *s, size_t n)
{
    appendf (buf, len, out, "\"");
    for (size_t i = 0; i < n; i++)
    {
        if (s[i] == '"' || s[i] == '\\') appendf (buf, len, out, "\\%c", s[i]);
        else if (s[i] < 0x20 || s[i] > 0x7e) appendf (buf, len, out, "\\%03u", s[i]);
        else appendf (buf, len, out, "%c", s[i]);
    }
    appendf (buf, len, out, "\"");
}

#define NAME_TEXT(n) dns_name_debug (n)

// Each rdata_*_display_r appends to buf at *out and returns buf.

// RFC 3597 generic form.
static const char *
rdata_unknown_display_r (const dns_rdata_unknown_t *rd, char *buf, size_t len, size_t *out)
{
    appendf (buf, len, out, "\\# %zu", rd->len);
    if (rd->len) appendf (buf, len, out, " ");
    for (size_t i = 0; i < rd->len; i++)
        appendf (buf, len, out, "%02x", rd->data[i]);
    return buf;
}

static const char *
rdata_a_display_r (const dns_rdata_a_t *rd, char *buf, size_t len, size_t *out)
{
    const uint8_t *a = rd->addr;
    appendf (buf, len, out, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
    return buf;
}

static const char *
rdata_aaaa_display_r (const dns_rdata_aaaa_t *rd, char *buf, size_t len, size_t *out)
{
    char addr[INET6_ADDRSTRLEN];
    if (!inet_ntop (AF_INET6, rd->addr, addr, sizeof addr))
        return rdata_unknown_display_r (
            &(dns_rdata_unknown_t){.data = rd->addr, .len = sizeof rd->addr}, buf, len, out);
    appendf (buf, len, out, "%s", addr);
    return buf;
}

// NS, CNAME, PTR, DNAME: a single domain name.
static const char *
rdata_name_display_r (const dns_name_t *name, char *buf, size_t len, size_t *out)
{
    appendf (buf, len, out, "%s", NAME_TEXT (name));
    return buf;
}

static const char *
rdata_mx_display_r (const dns_rdata_mx_t *rd, char *buf, size_t len, size_t *out)
{
    appendf (buf, len, out, "%u %s", (unsigned)rd->preference, NAME_TEXT (&rd->exchange));
    return buf;
}

static const char *
rdata_srv_display_r (const dns_rdata_srv_t *rd, char *buf, size_t len, size_t *out)
{
    appendf (buf,
             len,
             out,
             "%u %u %u %s",
             (unsigned)rd->priority,
             (unsigned)rd->weight,
             (unsigned)rd->port,
             NAME_TEXT (&rd->target));
    return buf;
}

static const char *
rdata_soa_display_r (const dns_rdata_soa_t *rd, char *buf, size_t len, size_t *out)
{
    appendf (buf,
             len,
             out,
             "%s %s %lu %lu %lu %lu %lu",
             NAME_TEXT (&rd->mname),
             NAME_TEXT (&rd->rname),
             (unsigned long)rd->serial,
             (unsigned long)rd->refresh,
             (unsigned long)rd->retry,
             (unsigned long)rd->expire,
             (unsigned long)rd->minimum);
    return buf;
}

static const char *
rdata_txt_display_r (const dns_rdata_txt_t *rd, char *buf, size_t len, size_t *out)
{
    const uint8_t *d = rd->data;
    for (size_t pos = 0; pos < rd->len; pos += 1 + d[pos])
    {
        if (pos) appendf (buf, len, out, " ");
        append_string (buf, len, out, d + pos + 1, d[pos]);
    }
    return buf;
}

#undef NAME_TEXT

static const char *
known_display_r (dns_type_t type, const dns_rdata_t *rd, char *buf, size_t len, size_t *out)
{
    switch (type)
    {
    case DNS_TYPE_A:
        return rdata_a_display_r (&rd->a, buf, len, out);
    case DNS_TYPE_AAAA:
        return rdata_aaaa_display_r (&rd->aaaa, buf, len, out);
    case DNS_TYPE_NS:
        return rdata_name_display_r (&rd->ns.nsdname, buf, len, out);
    case DNS_TYPE_CNAME:
        return rdata_name_display_r (&rd->cname.cname, buf, len, out);
    case DNS_TYPE_PTR:
        return rdata_name_display_r (&rd->ptr.ptrdname, buf, len, out);
    case DNS_TYPE_DNAME:
        return rdata_name_display_r (&rd->dname.target, buf, len, out);
    case DNS_TYPE_MX:
        return rdata_mx_display_r (&rd->mx, buf, len, out);
    case DNS_TYPE_SRV:
        return rdata_srv_display_r (&rd->srv, buf, len, out);
    case DNS_TYPE_SOA:
        return rdata_soa_display_r (&rd->soa, buf, len, out);
    case DNS_TYPE_TXT:
        return rdata_txt_display_r (&rd->txt, buf, len, out);
    default:
        return rdata_unknown_display_r (&rd->unknown, buf, len, out);
    }
}

const char *
dns_rdata_display_r (
    dns_type_t type, dns_class_t class, const dns_rdata_t *rdata, char *buf, size_t len)
{
    size_t out = 0;

    if (len == 0) return buf;
    buf[0] = '\0';

    if (dns_rdata_known (type, class)) known_display_r (type, rdata, buf, len, &out);
    else rdata_unknown_display_r (&rdata->unknown, buf, len, &out);
    return buf;
}
