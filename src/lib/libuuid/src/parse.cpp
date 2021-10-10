/*
* Copyright (c) 2021 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <uuid/uuid.h>

static const char upper_chars[] = "0123456789ABCDEF";
static const char lower_chars[] = "0123456789abcdef";

constexpr bool uuid_off_requires_sep(unsigned int i)
{
	return i == 4 || i == 6 || i == 8 || i == 10;
}

void uuid_unparse_internal(const uuid_t uu, char *out, const char *charset)
{
	for(unsigned int i = 0; i < 16; i++)
	{
		auto byte = uu[i];

		// If we require a separator right here, add it.
		if(uuid_off_requires_sep(i))
		{
			*out++ = '-';
		}

		// We go nibble by nibble
		*out++ = charset[byte >> 4];
		*out++ = charset[byte & 0xf];
	}

	// Add the null byte.
	*out = '\0';
}

void uuid_unparse_upper(const uuid_t uu, char *out)
{
	return uuid_unparse_internal(uu, out, upper_chars);
}

void uuid_unparse_lower(const uuid_t uu, char *out)
{
	return uuid_unparse_internal(uu, out, lower_chars);
}

void uuid_unparse(const uuid_t uu, char *out)
{
	return uuid_unparse_internal(uu, out, lower_chars);
}
