#include <string.h>
// Copy the NULL-terminated string src into dest, and
// return dest.
char *strcpy(char *dest, const char *src)
{
	do
	{
		*dest++ = *src++;
	}
	while (*src != 0);
        return dest;
}
