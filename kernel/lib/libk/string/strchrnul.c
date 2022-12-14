/*----------------------------------------------------------------------
 * Code taken from musl 1.1.16, licensed under the MIT license
 */
#include <limits.h>
#include <stdint.h>
#include <string.h>

#include <onyx/compiler.h>

#define ALIGN      (sizeof(size_t))
#define ONES       ((size_t) -1 / UCHAR_MAX)
#define HIGHS      (ONES * (UCHAR_MAX / 2 + 1))
#define HASZERO(x) (((x) -ONES) & ~(x) &HIGHS)

NO_ASAN
char *__strchrnul(const char *s, int c)
{
    size_t *w, k;

    c = (unsigned char) c;
    if (!c)
        return (char *) s + strlen(s);

    for (; (uintptr_t) s % ALIGN; s++)
        if (!*s || *(unsigned char *) s == c)
            return (char *) s;
    k = ONES * c;
    for (w = (void *) s; !HASZERO(*w) && !HASZERO(*w ^ k); w++)
        ;
    for (s = (void *) w; *s && *(unsigned char *) s != c; s++)
        ;
    return (char *) s;
}
