// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/******************************************************************************
 *
 * Module Name: utclib - ACPICA implementations of C library functions
 *
 * Copyright (C) 2000 - 2022, Intel Corp.
 *
 *****************************************************************************/


#define ACPI_CLIBRARY
#include "acpi.h"
#include "accommon.h"

/*
 * This module contains implementations of the standard C library functions
 * that are required by the ACPICA code at both application level and kernel
 * level.
 *
 * The module is an optional feature that can be used if a local/system
 * C library is not available. Some operating system kernels may not have
 * an internal C library.
 *
 * In general, these functions are less efficient than an inline or assembly
 * code implementation.
 *
 * These C functions and the associated prototypes are enabled by default
 * unless the ACPI_USE_SYSTEM_CLIBRARY symbol is defined. This is usually
 * automatically defined for the ACPICA applications such as iASL and
 * acpi_exec, so that these user-level applications use the local C library
 * instead of the functions in this module.
 */

/*******************************************************************************
 *
 * Functions implemented in this module:
 *
 * FUNCTION:    memcmp
 * FUNCTION:    memcpy
 * FUNCTION:    memset
 * FUNCTION:    strlen
 * FUNCTION:    strcpy
 * FUNCTION:    strncpy
 * FUNCTION:    strcmp
 * FUNCTION:    strchr
 * FUNCTION:    strncmp
 * FUNCTION:    strcat
 * FUNCTION:    strncat
 * FUNCTION:    strstr
 * FUNCTION:    strtoul
 * FUNCTION:    toupper
 * FUNCTION:    tolower
 * FUNCTION:    is* functions
 *
 ******************************************************************************/

#define _COMPONENT          ACPI_UTILITIES
	 ACPI_MODULE_NAME    ("utclib")


#ifndef ACPI_USE_SYSTEM_CLIBRARY    /* Entire module */


/*******************************************************************************
 *
 * FUNCTION:    memcmp
 *
 * PARAMETERS:  buffer1         - First Buffer
 *              buffer2         - Second Buffer
 *              count           - Maximum # of bytes to compare
 *
 * RETURN:      Index where Buffers mismatched, or 0 if Buffers matched
 *
 * DESCRIPTION: Compare two Buffers, with a maximum length
 *
 ******************************************************************************/

int
memcmp (
	void                            *Vbuffer1,
	void                            *Vbuffer2,
	acpi_size                       count)
{
	char                            *buffer1 = (char *) Vbuffer1;
	char                            *buffer2 = (char *) Vbuffer2;



	return ((count == ACPI_SIZE_MAX) ? 0 : ((unsigned char) *buffer1 -
		(unsigned char) *buffer2));
}


/*******************************************************************************
 *
 * FUNCTION:    memmove
 *
 * PARAMETERS:  dest        - Target of the copy
 *              src         - Source buffer to copy
 *              count       - Number of bytes to copy
 *
 * RETURN:      Dest
 *
 * DESCRIPTION: Copy arbitrary bytes of memory with respect to the overlapping
 *
 ******************************************************************************/

void *
memmove (
	void                            *dest,
	const void                      *src,
	acpi_size                       count)
{
	char                            *new = (char *) dest;
	char                            *old = (char *) src;


	if (old > new) {

		/* Copy from the beginning */

		while (count) {
			*new = *old;
			new++;
			old++;
			count--;
		}
	}
	else if (old < new) {

		/* Copy from the end */

		new = new + count - 1;
		old = old + count - 1;
		while (count) {
			*new = *old;
			new--;
			old--;
			count--;
		}
	}

	return (dest);
}


/*******************************************************************************
 *
 * FUNCTION:    memcpy
 *
 * PARAMETERS:  dest        - Target of the copy
 *              src         - Source buffer to copy
 *              count       - Number of bytes to copy
 *
 * RETURN:      Dest
 *
 * DESCRIPTION: Copy arbitrary bytes of memory
 *
 ******************************************************************************/

void *
memcpy (
	void                            *dest,
	const void                      *src,
	acpi_size                       count)
{
	char                            *new = (char *) dest;
	char                            *old = (char *) src;


	while (count) {
		*new = *old;
		new++;
		old++;
		count--;
	}

	return (dest);
}


/*******************************************************************************
 *
 * FUNCTION:    memset
 *
 * PARAMETERS:  dest        - Buffer to set
 *              value       - Value to set each byte of memory
 *              count       - Number of bytes to set
 *
 * RETURN:      Dest
 *
 * DESCRIPTION: Initialize a buffer to a known value.
 *
 ******************************************************************************/

void *
memset (
	void                            *dest,
	int                             value,
	acpi_size                       count)
{
	char                            *new = (char *) dest;


	while (count) {
		*new = (char) value;
		new++;
		count--;
	}

	return (dest);
}


/*******************************************************************************
 *
 * FUNCTION:    strlen
 *
 * PARAMETERS:  string              - Null terminated string
 *
 * RETURN:      Length
 *
 * DESCRIPTION: Returns the length of the input string
 *
 ******************************************************************************/


acpi_size
strlen (
	const char                      *string)
{
	u32                             length = 0;


	/* Count the string until a null is encountered */

	while (*string) {
		length++;
		string++;
	}

	return (length);
}


/*******************************************************************************
 *
 * FUNCTION:    strpbrk
 *
 * PARAMETERS:  string              - Null terminated string
 *              delimiters          - Delimiters to match
 *
 * RETURN:      The first occurrence in the string of any of the bytes in the
 *              delimiters
 *
 * DESCRIPTION: Search a string for any of a set of the delimiters
 *
 ******************************************************************************/

char *
strpbrk (
	const char                      *string,
	const char                      *delimiters)
{
	const char                      *delimiter;


	for ( ; *string != '\0'; ++string) {
		for (delimiter = delimiters; *delimiter != '\0'; delimiter++) {
			if (*string == *delimiter) {
				return (ACPI_CAST_PTR (char, string));
			}
		}
	}

	return (NULL);
}


/*******************************************************************************
 *
 * FUNCTION:    strtok
 *
 * PARAMETERS:  string              - Null terminated string
 *              delimiters          - Delimiters to match
 *
 * RETURN:      Pointer to the next token
 *
 * DESCRIPTION: Split string into tokens
 *
 ******************************************************************************/

char*
strtok (
	char                            *string,
	const char                      *delimiters)
{
	char                            *begin = string;
	static char                     *saved_ptr;


	if (begin == NULL) {
		if (saved_ptr == NULL) {
			return (NULL);
		}
		begin = saved_ptr;
	}

	saved_ptr = strpbrk (begin, delimiters);
	while (saved_ptr == begin) {
		*begin++ = '\0';
		saved_ptr = strpbrk (begin, delimiters);
	}

	if (saved_ptr) {
		*saved_ptr++ = '\0';
		return (begin);
	}
	else {
		return (NULL);
	}
}


/*******************************************************************************
 *
 * FUNCTION:    strcpy
 *
 * PARAMETERS:  dst_string      - Target of the copy
 *              src_string      - The source string to copy
 *
 * RETURN:      dst_string
 *
 * DESCRIPTION: Copy a null terminated string
 *
 ******************************************************************************/

char *
strcpy (
	char                            *dst_string,
	const char                      *src_string)
{
	char                            *string = dst_string;


	/* Move bytes brute force */

	while (*src_string) {
		*string = *src_string;

		string++;
		src_string++;
	}

	/* Null terminate */

	*string = 0;
	return (dst_string);
}


/*******************************************************************************
 *
 * FUNCTION:    strncpy
 *
 * PARAMETERS:  dst_string      - Target of the copy
 *              src_string      - The source string to copy
 *              count           - Maximum # of bytes to copy
 *
 * RETURN:      dst_string
 *
 * DESCRIPTION: Copy a null terminated string, with a maximum length
 *
 ******************************************************************************/

char *
strncpy (
	char                            *dst_string,
	const char                      *src_string,
	acpi_size                       count)
{
	char                            *string = dst_string;


	/* Copy the string */

	for (string = dst_string;
		count && (count--, (*string++ = *src_string++)); ) {;}

	/* Pad with nulls if necessary */

	while (count--) {
		*string = 0;
		string++;
	}

	/* Return original pointer */

	return (dst_string);
}


/*******************************************************************************
 *
 * FUNCTION:    strcmp
 *
 * PARAMETERS:  string1         - First string
 *              string2         - Second string
 *
 * RETURN:      Index where strings mismatched, or 0 if strings matched
 *
 * DESCRIPTION: Compare two null terminated strings
 *
 ******************************************************************************/

int
strcmp (
	const char                      *string1,
	const char                      *string2)
{


	for ( ; (*string1 == *string2); string2++) {
		if (!*string1++) {
			return (0);
		}
	}

	return ((unsigned char) *string1 - (unsigned char) *string2);
}


/*******************************************************************************
 *
 * FUNCTION:    strchr
 *
 * PARAMETERS:  string          - Search string
 *              ch              - character to search for
 *
 * RETURN:      Ptr to char or NULL if not found
 *
 * DESCRIPTION: Search a string for a character
 *
 ******************************************************************************/

char *
strchr (
	const char                      *string,
	int                             ch)
{


	for ( ; (*string); string++) {
		if ((*string) == (char) ch) {
			return ((char *) string);
		}
	}

	return (NULL);
}


/*******************************************************************************
 *
 * FUNCTION:    strncmp
 *
 * PARAMETERS:  string1         - First string
 *              string2         - Second string
 *              count           - Maximum # of bytes to compare
 *
 * RETURN:      Index where strings mismatched, or 0 if strings matched
 *
 * DESCRIPTION: Compare two null terminated strings, with a maximum length
 *
 ******************************************************************************/

int
strncmp (
	const char                      *string1,
	const char                      *string2,
	acpi_size                       count)
{


	for ( ; count-- && (*string1 == *string2); string2++) {
		if (!*string1++) {
			return (0);
		}
	}

	return ((count == ACPI_SIZE_MAX) ? 0 : ((unsigned char) *string1 -
		(unsigned char) *string2));
}


/*******************************************************************************
 *
 * FUNCTION:    strcat
 *
 * PARAMETERS:  dst_string      - Target of the copy
 *              src_string      - The source string to copy
 *
 * RETURN:      dst_string
 *
 * DESCRIPTION: Append a null terminated string to a null terminated string
 *
 ******************************************************************************/

char *
strcat (
	char                            *dst_string,
	const char                      *src_string)
{
	char                            *string;


	/* Find end of the destination string */

	for (string = dst_string; *string++; ) { ; }

	/* Concatenate the string */

	for (--string; (*string++ = *src_string++); ) { ; }

	return (dst_string);
}


/*******************************************************************************
 *
 * FUNCTION:    strncat
 *
 * PARAMETERS:  dst_string      - Target of the copy
 *              src_string      - The source string to copy
 *              count           - Maximum # of bytes to copy
 *
 * RETURN:      dst_string
 *
 * DESCRIPTION: Append a null terminated string to a null terminated string,
 *              with a maximum count.
 *
 ******************************************************************************/

char *
strncat (
	char                            *dst_string,
	const char                      *src_string,
	acpi_size                       count)
{
	char                            *string;


	if (count) {

		/* Find end of the destination string */

		for (string = dst_string; *string++; ) { ; }

		/* Concatenate the string */

		for (--string; (*string++ = *src_string++) && --count; ) { ; }

		/* Null terminate if necessary */

		if (!count) {
			*string = 0;
		}
	}

	return (dst_string);
}


/*******************************************************************************
 *
 * FUNCTION:    strstr
 *
 * PARAMETERS:  string1         - Target string
 *              string2         - Substring to search for
 *
 * RETURN:      Where substring match starts, Null if no match found
 *
 * DESCRIPTION: Checks if String2 occurs in String1. This is not really a
 *              full implementation of strstr, only sufficient for command
 *              matching
 *
 ******************************************************************************/

char *
strstr (
	char                            *string1,
	char                            *string2)
{
	acpi_size                       length;


	length = strlen (string2);
	if (!length) {
		return (string1);
	}

	while (strlen (string1) >= length) {
		if (memcmp (string1, string2, length) == 0) {
			return (string1);
		}
		string1++;
	}

	return (NULL);
}


/*******************************************************************************
 *
 * FUNCTION:    strtoul
 *
 * PARAMETERS:  string          - Null terminated string
 *              terminator      - Where a pointer to the terminating byte is
 *                                returned
 *              base            - Radix of the string
 *
 * RETURN:      Converted value
 *
 * DESCRIPTION: Convert a string into a 32-bit unsigned value.
 *              Note: use strtoul64 for 64-bit integers.
 *
 ******************************************************************************/

u32
strtoul (
	const char                      *string,
	char                            **terminator,
	u32                             base)
{
	u32                             converted = 0;
	u32                             index;
	u32                             sign;
	const char                      *string_start;
	u32                             return_value = 0;
	acpi_status                     status = AE_OK;


	/*
	 * Save the value of the pointer to the buffer's first
	 * character, save the current errno value, and then
	 * skip over any white space in the buffer:
	 */
	string_start = string;
	while (isspace (*string) || *string == '\t') {
		++string;
	}

	/*
	 * The buffer may contain an optional plus or minus sign.
	 * If it does, then skip over it but remember what is was:
	 */
	if (*string == '-') {
		sign = ACPI_SIGN_NEGATIVE;
		++string;
	}
	else if (*string == '+') {
		++string;
		sign = ACPI_SIGN_POSITIVE;
	}
	else {
		sign = ACPI_SIGN_POSITIVE;
	}

	/*
	 * If the input parameter Base is zero, then we need to
	 * determine if it is octal, decimal, or hexadecimal:
	 */
	if (base == 0) {
		if (*string == '0') {
			if (tolower (*(++string)) == 'x') {
				base = 16;
				++string;
			}
			else {
				base = 8;
			}
		}
		else {
			base = 10;
		}
	}
	else if (base < 2 || base > 36) {
		/*
		 * The specified Base parameter is not in the domain of
		 * this function:
		 */
		goto done;
	}

	/*
	 * For octal and hexadecimal bases, skip over the leading
	 * 0 or 0x, if they are present.
	 */
	if (base == 8 && *string == '0') {
		string++;
	}

	if (base == 16 &&
		*string == '0' &&
		tolower (*(++string)) == 'x') {
		string++;
	}

	/*
	 * Main loop: convert the string to an unsigned long:
	 */
	while (*string) {
		if (isdigit (*string)) {
			index = (u32) ((u8) *string - '0');
		}
		else {
			index = (u32) toupper (*string);
			if (isupper (index)) {
				index = index - 'A' + 10;
			}
			else {
				goto done;
			}
		}

		if (index >= base) {
			goto done;
		}

		/*
		 * Check to see if value is out of range:
		 */

		if (return_value > ((ACPI_UINT32_MAX - (u32) index) /
				   (u32) base)) {
			status = AE_ERROR;
			return_value = 0;          /* reset */
		}
		else {
			return_value *= base;
			return_value += index;
			converted = 1;
		}

		++string;
	}

done:
	/*
	 * If appropriate, update the caller's pointer to the next
	 * unconverted character in the buffer.
	 */
	if (terminator) {
		if (converted == 0 && return_value == 0 && string != NULL) {
			*terminator = (char *) string_start;
		}
		else {
			*terminator = (char *) string;
		}
	}

	if (status == AE_ERROR) {
		return_value = ACPI_UINT32_MAX;
	}

	/*
	 * If a minus sign was present, then "the conversion is negated":
	 */
	if (sign == ACPI_SIGN_NEGATIVE) {
		return_value = (ACPI_UINT32_MAX - return_value) + 1;
	}

	return (return_value);
}


/*******************************************************************************
 *
 * FUNCTION:    toupper
 *
 * PARAMETERS:  c           - Character to convert
 *
 * RETURN:      Converted character as an int
 *
 * DESCRIPTION: Convert character to uppercase
 *
 ******************************************************************************/

int
toupper (
	int                             c)
{

	return (islower(c) ? ((c)-0x20) : (c));
}


/*******************************************************************************
 *
 * FUNCTION:    tolower
 *
 * PARAMETERS:  c           - Character to convert
 *
 * RETURN:      Converted character as an int
 *
 * DESCRIPTION: Convert character to lowercase
 *
 ******************************************************************************/

int
tolower (
	int                             c)
{

	return (isupper(c) ? ((c)+0x20) : (c));
}


/*******************************************************************************
 *
 * FUNCTION:    is* function array
 *
 * DESCRIPTION: is* functions use the ctype table below
 *
 ******************************************************************************/

const u8 acpi_gbl_ctypes[257] = {
	_ACPI_CN,            /* 0x00     0 NUL */
	_ACPI_CN,            /* 0x01     1 SOH */
	_ACPI_CN,            /* 0x02     2 STX */
	_ACPI_CN,            /* 0x03     3 ETX */
	_ACPI_CN,            /* 0x04     4 EOT */
	_ACPI_CN,            /* 0x05     5 ENQ */
	_ACPI_CN,            /* 0x06     6 ACK */
	_ACPI_CN,            /* 0x07     7 BEL */
	_ACPI_CN,            /* 0x08     8 BS  */
	_ACPI_CN|_ACPI_SP,   /* 0x09     9 TAB */
	_ACPI_CN|_ACPI_SP,   /* 0x0A    10 LF  */
	_ACPI_CN|_ACPI_SP,   /* 0x0B    11 VT  */
	_ACPI_CN|_ACPI_SP,   /* 0x0C    12 FF  */
	_ACPI_CN|_ACPI_SP,   /* 0x0D    13 CR  */
	_ACPI_CN,            /* 0x0E    14 SO  */
	_ACPI_CN,            /* 0x0F    15 SI  */
	_ACPI_CN,            /* 0x10    16 DLE */
	_ACPI_CN,            /* 0x11    17 DC1 */
	_ACPI_CN,            /* 0x12    18 DC2 */
	_ACPI_CN,            /* 0x13    19 DC3 */
	_ACPI_CN,            /* 0x14    20 DC4 */
	_ACPI_CN,            /* 0x15    21 NAK */
	_ACPI_CN,            /* 0x16    22 SYN */
	_ACPI_CN,            /* 0x17    23 ETB */
	_ACPI_CN,            /* 0x18    24 CAN */
	_ACPI_CN,            /* 0x19    25 EM  */
	_ACPI_CN,            /* 0x1A    26 SUB */
	_ACPI_CN,            /* 0x1B    27 ESC */
	_ACPI_CN,            /* 0x1C    28 FS  */
	_ACPI_CN,            /* 0x1D    29 GS  */
	_ACPI_CN,            /* 0x1E    30 RS  */
	_ACPI_CN,            /* 0x1F    31 US  */
	_ACPI_XS|_ACPI_SP,   /* 0x20    32 ' ' */
	_ACPI_PU,            /* 0x21    33 '!' */
	_ACPI_PU,            /* 0x22    34 '"' */
	_ACPI_PU,            /* 0x23    35 '#' */
	_ACPI_PU,            /* 0x24    36 '$' */
	_ACPI_PU,            /* 0x25    37 '%' */
	_ACPI_PU,            /* 0x26    38 '&' */
	_ACPI_PU,            /* 0x27    39 ''' */
	_ACPI_PU,            /* 0x28    40 '(' */
	_ACPI_PU,            /* 0x29    41 ')' */
	_ACPI_PU,            /* 0x2A    42 '*' */
	_ACPI_PU,            /* 0x2B    43 '+' */
	_ACPI_PU,            /* 0x2C    44 ',' */
	_ACPI_PU,            /* 0x2D    45 '-' */
	_ACPI_PU,            /* 0x2E    46 '.' */
	_ACPI_PU,            /* 0x2F    47 '/' */
	_ACPI_XD|_ACPI_DI,   /* 0x30    48 '0' */
	_ACPI_XD|_ACPI_DI,   /* 0x31    49 '1' */
	_ACPI_XD|_ACPI_DI,   /* 0x32    50 '2' */
	_ACPI_XD|_ACPI_DI,   /* 0x33    51 '3' */
	_ACPI_XD|_ACPI_DI,   /* 0x34    52 '4' */
	_ACPI_XD|_ACPI_DI,   /* 0x35    53 '5' */
	_ACPI_XD|_ACPI_DI,   /* 0x36    54 '6' */
	_ACPI_XD|_ACPI_DI,   /* 0x37    55 '7' */
	_ACPI_XD|_ACPI_DI,   /* 0x38    56 '8' */
	_ACPI_XD|_ACPI_DI,   /* 0x39    57 '9' */
	_ACPI_PU,            /* 0x3A    58 ':' */
	_ACPI_PU,            /* 0x3B    59 ';' */
	_ACPI_PU,            /* 0x3C    60 '<' */
	_ACPI_PU,            /* 0x3D    61 '=' */
	_ACPI_PU,            /* 0x3E    62 '>' */
	_ACPI_PU,            /* 0x3F    63 '?' */
	_ACPI_PU,            /* 0x40    64 '@' */
	_ACPI_XD|_ACPI_UP,   /* 0x41    65 'A' */
	_ACPI_XD|_ACPI_UP,   /* 0x42    66 'B' */
	_ACPI_XD|_ACPI_UP,   /* 0x43    67 'C' */
	_ACPI_XD|_ACPI_UP,   /* 0x44    68 'D' */
	_ACPI_XD|_ACPI_UP,   /* 0x45    69 'E' */
	_ACPI_XD|_ACPI_UP,   /* 0x46    70 'F' */
	_ACPI_UP,            /* 0x47    71 'G' */
	_ACPI_UP,            /* 0x48    72 'H' */
	_ACPI_UP,            /* 0x49    73 'I' */
	_ACPI_UP,            /* 0x4A    74 'J' */
	_ACPI_UP,            /* 0x4B    75 'K' */
	_ACPI_UP,            /* 0x4C    76 'L' */
	_ACPI_UP,            /* 0x4D    77 'M' */
	_ACPI_UP,            /* 0x4E    78 'N' */
	_ACPI_UP,            /* 0x4F    79 'O' */
	_ACPI_UP,            /* 0x50    80 'P' */
	_ACPI_UP,            /* 0x51    81 'Q' */
	_ACPI_UP,            /* 0x52    82 'R' */
	_ACPI_UP,            /* 0x53    83 'S' */
	_ACPI_UP,            /* 0x54    84 'T' */
	_ACPI_UP,            /* 0x55    85 'U' */
	_ACPI_UP,            /* 0x56    86 'V' */
	_ACPI_UP,            /* 0x57    87 'W' */
	_ACPI_UP,            /* 0x58    88 'X' */
	_ACPI_UP,            /* 0x59    89 'Y' */
	_ACPI_UP,            /* 0x5A    90 'Z' */
	_ACPI_PU,            /* 0x5B    91 '[' */
	_ACPI_PU,            /* 0x5C    92 '\' */
	_ACPI_PU,            /* 0x5D    93 ']' */
	_ACPI_PU,            /* 0x5E    94 '^' */
	_ACPI_PU,            /* 0x5F    95 '_' */
	_ACPI_PU,            /* 0x60    96 '`' */
	_ACPI_XD|_ACPI_LO,   /* 0x61    97 'a' */
	_ACPI_XD|_ACPI_LO,   /* 0x62    98 'b' */
	_ACPI_XD|_ACPI_LO,   /* 0x63    99 'c' */
	_ACPI_XD|_ACPI_LO,   /* 0x64   100 'd' */
	_ACPI_XD|_ACPI_LO,   /* 0x65   101 'e' */
	_ACPI_XD|_ACPI_LO,   /* 0x66   102 'f' */
	_ACPI_LO,            /* 0x67   103 'g' */
	_ACPI_LO,            /* 0x68   104 'h' */
	_ACPI_LO,            /* 0x69   105 'i' */
	_ACPI_LO,            /* 0x6A   106 'j' */
	_ACPI_LO,            /* 0x6B   107 'k' */
	_ACPI_LO,            /* 0x6C   108 'l' */
	_ACPI_LO,            /* 0x6D   109 'm' */
	_ACPI_LO,            /* 0x6E   110 'n' */
	_ACPI_LO,            /* 0x6F   111 'o' */
	_ACPI_LO,            /* 0x70   112 'p' */
	_ACPI_LO,            /* 0x71   113 'q' */
	_ACPI_LO,            /* 0x72   114 'r' */
	_ACPI_LO,            /* 0x73   115 's' */
	_ACPI_LO,            /* 0x74   116 't' */
	_ACPI_LO,            /* 0x75   117 'u' */
	_ACPI_LO,            /* 0x76   118 'v' */
	_ACPI_LO,            /* 0x77   119 'w' */
	_ACPI_LO,            /* 0x78   120 'x' */
	_ACPI_LO,            /* 0x79   121 'y' */
	_ACPI_LO,            /* 0x7A   122 'z' */
	_ACPI_PU,            /* 0x7B   123 '{' */
	_ACPI_PU,            /* 0x7C   124 '|' */
	_ACPI_PU,            /* 0x7D   125 '}' */
	_ACPI_PU,            /* 0x7E   126 '~' */
	_ACPI_CN,            /* 0x7F   127 DEL */

	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  /* 0x80 to 0x8F    */
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  /* 0x90 to 0x9F    */
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  /* 0xA0 to 0xAF    */
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  /* 0xB0 to 0xBF    */
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  /* 0xC0 to 0xCF    */
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  /* 0xD0 to 0xDF    */
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  /* 0xE0 to 0xEF    */
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  /* 0xF0 to 0xFF    */
	0                                 /* 0x100 */
};


#endif /* ACPI_USE_SYSTEM_CLIBRARY */
