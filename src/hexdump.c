#include <ctype.h>
#include <hexdump.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define BYTES_PER_LINE 16

void
hexdump(const uint8_t *buf, size_t buf_len)
{
    size_t offset = 0;

    while (offset < buf_len)
    {
        size_t chunk_len =
            (buf_len - offset < BYTES_PER_LINE) ? (buf_len - offset) : BYTES_PER_LINE;

        printf("%08zX  ", offset);

        for (size_t i = 0; i < BYTES_PER_LINE; i++)
        {
            if (i < chunk_len)
            {
                printf("%02X ", buf[offset + i]);
            }
            else
            {
                printf("   ");
            }
            if (i == 7)
            {
                printf(" ");
            }
        }

        printf(" |");

        for (size_t i = 0; i < chunk_len; i++)
        {
            uint8_t c = buf[offset + i];
            if (isprint(c))
            {
                putchar(c);
            }
            else
            {
                putchar('.');
            }
        }
        printf("|\n");

        offset += chunk_len;
    }
    printf("%08zX\n", offset);
}
