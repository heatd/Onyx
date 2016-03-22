#include <string.h>
// Concatenate the NULL-terminated string src onto
// the end of dest, and return dest.
char *strcat(char *dest, const char *src)
{
	while(*dest != '\0'){
		++dest;
	}
	while(*src != '\0'){
		*dest = *src;
		++src;
		++dest;
	}
	*dest = '\0';
	return dest;
}
