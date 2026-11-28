#define _POSIX_C_SOURCE 200809L

#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "dns/header.h"
#include "dns/name.h"
#include "dns/params/class.h"
#include "dns/params/type.h"
#include "dns/question.h"
#include "dns/record.h"

#define TIMEOUT_MS 3000
#define TRIES 3
#define UDP_MAX 512
#define MSG_MAX 65535

#ifndef NI_MAXHOST
#define NI_MAXHOST 1025
#endif

static GString   *line;
static bool       uncompressed;
static uint8_t    uncompressed_buf[DNS_RECORD_NAMES_MAX][MSG_MAX];
static dns_name_t uncompressed_names[DNS_RECORD_NAMES_MAX];

static void
usage (void)
{
    fprintf (stderr,
             "usage: query [@server] [-p port] [+tcp] [+uncompressed] [+[no]FLAG ...] name [type] "
             "[class]\n"
             "       FLAG: qr aa tc rd ra z ad cd (default: rd on, others off)\n");
    exit (1);
}

static bool
parse_flag (const char *a, dns_header_t *hdr)
{
    if ('+' != a[0]) return false;

    bool        on = 0 != strncmp (a + 1, "no", 2);
    const char *f  = on ? a + 1 : a + 3;
    struct
    {
        const char *name;
        bool       *bit;
    } flags[] = {
        {"qr", &hdr->qr},
        {"aa", &hdr->aa},
        {"tc", &hdr->tc},
        {"rd", &hdr->rd},
        {"ra", &hdr->ra},
        {"z", &hdr->z},
        {"ad", &hdr->ad},
        {"cd", &hdr->cd},
    };
    for (size_t i = 0; i < sizeof flags / sizeof flags[0]; i++)
    {
        if (0 == strcmp (f, flags[i].name))
        {
            *flags[i].bit = on;
            return true;
        }
    }
    return false;
}

static const char *
default_server (void)
{
    static char addr[256];
    FILE       *fp = fopen ("/etc/resolv.conf", "r");
    char        line[512];

    if (NULL != fp)
    {
        while (NULL != fgets (line, sizeof line, fp))
        {
            if (1 == sscanf (line, " nameserver %255s", addr))
            {
                fclose (fp);
                return addr;
            }
        }
        fclose (fp);
    }
    return "127.0.0.1";
}

static uint16_t
random_id (void)
{
    uint16_t id = 0;
    FILE    *fp = fopen ("/dev/urandom", "rb");
    if (NULL == fp || 1 != fread (&id, sizeof id, 1, fp))
    {
        struct timespec ts;
        clock_gettime (CLOCK_REALTIME, &ts);
        id = (uint16_t)(ts.tv_nsec ^ getpid ());
    }
    if (NULL != fp) fclose (fp);
    return id;
}

static long
elapsed_ms (const struct timespec *start)
{
    struct timespec now;
    clock_gettime (CLOCK_MONOTONIC, &now);
    return (now.tv_sec - start->tv_sec) * 1000 + (now.tv_nsec - start->tv_nsec) / 1000000;
}

static bool
wait_readable (int fd, int timeout_ms)
{
    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    return 1 == poll (&pfd, 1, timeout_ms);
}

static int
connect_to (const struct addrinfo *ai)
{
    int fd = socket (ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) return -1;
    if (connect (fd, ai->ai_addr, ai->ai_addrlen) < 0)
    {
        close (fd);
        return -1;
    }
    return fd;
}

static ssize_t
exchange_udp (const struct addrinfo *ai, const uint8_t *q, size_t qlen, uint8_t *r, size_t rmax)
{
    int fd = connect_to (ai);
    if (fd < 0) return -1;

    ssize_t n = -1;
    for (int i = 0; i < TRIES && n < 0; i++)
    {
        if (send (fd, q, qlen, 0) != (ssize_t)qlen) break;
        while (wait_readable (fd, TIMEOUT_MS))
        {
            n = recv (fd, r, rmax, 0);
            if (2 <= n && r[0] == q[0] && r[1] == q[1]) break;
            n = -1;
        }
    }

    close (fd);
    return n;
}

static bool
read_full (int fd, uint8_t *buf, size_t len)
{
    for (size_t got = 0; got < len;)
    {
        if (!wait_readable (fd, TIMEOUT_MS)) return false;
        ssize_t n = recv (fd, buf + got, len - got, 0);
        if (n <= 0) return false;
        got += n;
    }
    return true;
}

static ssize_t
exchange_tcp (const struct addrinfo *ai, const uint8_t *q, size_t qlen, uint8_t *r, size_t rmax)
{
    int fd = connect_to (ai);
    if (fd < 0) return -1;

    uint8_t prefix[2] = {qlen >> 8, qlen & 0xff};
    ssize_t n         = -1;
    if (2 == send (fd, prefix, 2, 0) && send (fd, q, qlen, 0) == (ssize_t)qlen &&
        read_full (fd, prefix, 2))
    {
        size_t len = (size_t)prefix[0] << 8 | prefix[1];
        if (len <= rmax && read_full (fd, r, len)) n = len;
    }

    close (fd);
    return n;
}

static dns_error_t
uncompress_record (const dns_cursor_t *p, dns_record_t *rr)
{
    dns_record_t    out                         = *rr;
    dns_name_ref_t *names[DNS_RECORD_NAMES_MAX] = {&out.name};
    size_t          n                           = 1;
    if (dns_rdata_known (rr->type, rr->class))
    {
        switch (rr->type)
        {
        case DNS_TYPE_NS:
            names[n++] = &out.rdata.ns.nsdname;
            break;
        case DNS_TYPE_CNAME:
            names[n++] = &out.rdata.cname.cname;
            break;
        case DNS_TYPE_PTR:
            names[n++] = &out.rdata.ptr.ptrdname;
            break;
        case DNS_TYPE_DNAME:
            names[n++] = &out.rdata.dname.target;
            break;
        case DNS_TYPE_MX:
            names[n++] = &out.rdata.mx.exchange;
            break;
        case DNS_TYPE_SRV:
            names[n++] = &out.rdata.srv.target;
            break;
        case DNS_TYPE_SOA:
            names[n++] = &out.rdata.soa.mname;
            names[n++] = &out.rdata.soa.rname;
            break;
        case DNS_TYPE_MD:
            names[n++] = &out.rdata.md.madname;
            break;
        case DNS_TYPE_MF:
            names[n++] = &out.rdata.mf.madname;
            break;
        case DNS_TYPE_MB:
            names[n++] = &out.rdata.mb.madname;
            break;
        case DNS_TYPE_MG:
            names[n++] = &out.rdata.mg.mgmname;
            break;
        case DNS_TYPE_MR:
            names[n++] = &out.rdata.mr.newname;
            break;
        case DNS_TYPE_MINFO:
            names[n++] = &out.rdata.minfo.rmailbx;
            names[n++] = &out.rdata.minfo.emailbx;
            break;
        default: // no domain names
            break;
        }
    }

    dns_error_t err = DNS_OK;
    for (size_t i = 0; i < n; i++)
    {
        dns_error_t nerr = dns_name_to_uncompressed (names[i], p, &uncompressed_names[i]);
        if (!dns_is_ok (nerr)) return nerr;
        err = dns_merge_soft (err, nerr);
        dns_name_to_ref (&uncompressed_names[i], names[i]);
    }
    *rr = out;
    return err;
}

static bool
print_records (const char *title, unsigned count, dns_cursor_t *p)
{
    if (0 == count) return true;

    printf ("\n;; %s SECTION:\n", title);
    for (unsigned i = 0; i < count; i++)
    {
        dns_record_t record;
        dns_error_t  err = dns_record_from_wire (p, &record);
        if (DNS_OK != err)
            printf (";; error in %s section, record %u: %s\n", title, i + 1, dns_error_str (err));
        if (!dns_is_ok (err)) return false;
        if (uncompressed)
        {
            dns_error_t xerr = uncompress_record (p, &record);
            if (DNS_OK != xerr && xerr != err)
                printf (
                    ";; error in %s section, record %u: %s\n", title, i + 1, dns_error_str (xerr));
        }
        g_string_truncate (line, 0);
        puts (dns_record_debug (&record, line)->str);
    }
    return true;
}

static bool
print_reply (uint8_t *msg, size_t len)
{
    static dns_cursor_t parser;
    dns_cursor_init (&parser, msg, len);

    dns_header_t header;
    dns_error_t  err = dns_header_from_wire (&parser, &header);
    if (DNS_OK != err)
    {
        printf (";; error in header: %s\n", dns_error_str (err));
        return false;
    }

    const dns_header_t *hdr = &header;
    g_string_truncate (line, 0);
    printf (";; ->>HEADER<<- %s\n", dns_header_debug (hdr, line)->str);

    bool ok = true;
    if (hdr->qdcount) printf ("\n;; QUESTION SECTION:\n");
    for (unsigned i = 0; ok && i < hdr->qdcount; i++)
    {
        dns_question_t question;
        if (DNS_OK != (err = dns_question_from_wire (&parser, &question)))
            printf (";; error in QUESTION section: %s\n", dns_error_str (err));
        if (!dns_is_ok (err))
        {
            ok = false;
            break;
        }
        dns_question_t *q = &question;
        if (uncompressed)
        {
            err = dns_name_to_uncompressed (&q->qname, &parser, &uncompressed_names[0]);
            if (DNS_OK != err) printf (";; error in QUESTION section: %s\n", dns_error_str (err));
            if (dns_is_ok (err)) dns_name_to_ref (&uncompressed_names[0], &q->qname);
        }
        g_string_truncate (line, 0);
        printf (";%s\n", dns_question_debug (q, line)->str);
    }

    ok = ok && print_records ("ANSWER", hdr->ancount, &parser) &&
         print_records ("AUTHORITY", hdr->nscount, &parser) &&
         print_records ("ADDITIONAL", hdr->arcount, &parser);
    size_t off = cursor_bytes (&parser.cur);
    if (ok && off != len) printf (";; warning: %zu trailing octets\n", len - off);

    return ok;
}

int
main (int argc, char **argv)
{
    line = g_string_new (NULL);
    for (size_t i = 0; i < DNS_RECORD_NAMES_MAX; i++)
        uncompressed_names[i] =
            (dns_name_t){.ptr = uncompressed_buf[i], .cap = sizeof uncompressed_buf[i]};

    const char  *server    = NULL;
    const char  *port      = "53";
    const char  *qname     = NULL;
    bool         tcp       = false;
    bool         have_type = false, have_class = false;
    dns_type_t   qtype  = DNS_TYPE_A;
    dns_class_t  qclass = DNS_CLASS_IN;
    dns_header_t hdr = {.id = random_id (), .opcode = DNS_OPCODE_QUERY, .rd = true, .qdcount = 1};

    for (int i = 1; i < argc; i++)
    {
        const char *a = argv[i];
        if ('@' == a[0] && a[1]) server = a + 1;
        else if (0 == strcmp (a, "-p") && i + 1 < argc) port = argv[++i];
        else if (0 == strcmp (a, "+tcp")) tcp = true;
        else if (0 == strcmp (a, "+uncompressed")) uncompressed = true;
        else if (parse_flag (a, &hdr)) continue;
        else if ('+' == a[0]) usage ();
        else if (NULL == qname) qname = a;
        else if (!have_type && DNS_OK == dns_type_from_string (&qtype, a)) have_type = true;
        else if (!have_class && DNS_OK == dns_class_from_string (&qclass, a)) have_class = true;
        else usage ();
    }
    if (NULL == qname) usage ();
    if (NULL == server) server = default_server ();

    uint8_t     name_buf[UDP_MAX];
    dns_name_t  name = {.ptr = name_buf, .cap = sizeof name_buf};
    dns_error_t err  = dns_name_from_string (&name, qname);
    if (DNS_OK != err) fprintf (stderr, "query: bad name '%s': %s\n", qname, dns_error_str (err));
    if (!dns_is_ok (err)) return 1;

    dns_question_t q = {.qtype = qtype, .qclass = qclass};
    dns_name_to_ref (&name, &q.qname);
    uint8_t             query[UDP_MAX];
    static dns_cursor_t writer;
    dns_cursor_init (&writer, query, sizeof query);
    err = dns_header_to_wire (&writer, &hdr);
    if (DNS_OK == err) err = dns_question_to_wire (&writer, &q, true);
    size_t qlen = cursor_bytes (&writer.cur);
    if (!dns_is_ok (err))
    {
        fprintf (stderr, "query: cannot build query: %s\n", dns_error_str (err));
        return 1;
    }

    struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = tcp ? SOCK_STREAM : SOCK_DGRAM};
    struct addrinfo *ai;
    int              gai = getaddrinfo (server, port, &hints, &ai);
    if (0 != gai)
    {
        fprintf (stderr, "query: %s: %s\n", server, gai_strerror (gai));
        return 1;
    }

    char host[NI_MAXHOST] = "?";
    getnameinfo (ai->ai_addr, ai->ai_addrlen, host, sizeof host, NULL, 0, NI_NUMERICHOST);

    g_string_assign (line, "");
    dns_type_to_string (qtype, line);
    g_string_append_c (line, ' ');
    dns_class_to_string (qclass, line);
    printf ("; <<>> query <<>> %s %s\n", qname, line->str);

    static uint8_t  reply[MSG_MAX];
    struct timespec start;
    clock_gettime (CLOCK_MONOTONIC, &start);

    ssize_t rlen;
    if (tcp)
    {
        rlen = exchange_tcp (ai, query, qlen, reply, sizeof reply);
    }
    else
    {
        rlen = exchange_udp (ai, query, qlen, reply, sizeof reply);
        if (DNS_HEADER_SIZE <= rlen && (reply[2] & 0x02))
        {
            printf (";; Truncated, retrying in TCP mode.\n");
            struct addrinfo  thints = {.ai_family = ai->ai_family, .ai_socktype = SOCK_STREAM};
            struct addrinfo *tai;
            tcp = true;
            if (0 == getaddrinfo (host, port, &thints, &tai))
            {
                rlen = exchange_tcp (tai, query, qlen, reply, sizeof reply);
                freeaddrinfo (tai);
            }
            else
            {
                rlen = -1;
            }
        }
    }
    long ms = elapsed_ms (&start);
    freeaddrinfo (ai);

    if (rlen < 0)
    {
        printf (";; connection timed out; no servers could be reached\n");
        return 9;
    }

    bool ok = print_reply (reply, (size_t)rlen);

    printf ("\n;; Query time: %ld msec\n", ms);
    printf (";; SERVER: %s#%s(%s)\n", host, port, tcp ? "TCP" : "UDP");
    printf (";; MSG SIZE  rcvd: %zd\n", rlen);

    return ok ? 0 : 10;
}
