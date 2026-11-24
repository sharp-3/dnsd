#include "utils/string.h"

bool
str_equal_nocase (const char *a, const char *b)
{
    for (; *a && *b; a++, b++)
        if (ascii_tolower (*a) != ascii_tolower (*b)) return false;
    return *a == *b;
}
