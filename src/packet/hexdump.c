#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "packet/hexdump.h"

#define BYTES_PER_LINE 16

void
hexdump (const uint8_t *pkt, size_t nbytes_len)
{
    size_t nbytes_off = 0;

    while (nbytes_off < nbytes_len)
    {
        size_t chunk_len =
            (nbytes_len - nbytes_off < BYTES_PER_LINE) ? (nbytes_len - nbytes_off) : BYTES_PER_LINE;

        printf ("%08zX  ", nbytes_off);

        for (size_t i = 0; i < BYTES_PER_LINE; i++)
        {
            if (i < chunk_len) printf ("%02X ", pkt[nbytes_off + i]);
            else printf ("   ");
            if (i == 7) printf (" ");
        }

        printf (" |");

        for (size_t i = 0; i < chunk_len; i++)
        {
            uint8_t c = pkt[nbytes_off + i];
            if (isprint (c)) putchar (c);
            else putchar ('.');
        }
        printf ("|\n");

        nbytes_off += chunk_len;
    }
    printf ("%08zX\n", nbytes_off);
}
