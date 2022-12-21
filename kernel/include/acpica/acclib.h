/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/******************************************************************************
 *
 * Name: acclib.h -- C library support. Prototypes for the (optional) local
 *                   implementations of required C library functions.
 *
 * Copyright (C) 2000 - 2022, Intel Corp.
 *
 *****************************************************************************/


#ifndef _ACCLIB_H
#define _ACCLIB_H


/*
 * Prototypes and macros for local implementations of C library functions
 */

/* is* functions. The acpi_gbl_Ctypes array is defined in utclib.c */

extern const u8 acpi_gbl_ctypes[];

#define _ACPI_XA     0x00    /* extra alphabetic - not supported */
#define _ACPI_XS     0x40    /* extra space */
#define _ACPI_BB     0x00    /* BEL, BS, etc. - not supported */
#define _ACPI_CN     0x20    /* CR, FF, HT, NL, VT */
#define _ACPI_DI     0x04    /* '0'-'9' */
#define _ACPI_LO     0x02    /* 'a'-'z' */
#define _ACPI_PU     0x10    /* punctuation */
#define _ACPI_SP     0x08    /* space, tab, CR, LF, VT, FF */
#define _ACPI_UP     0x01    /* 'A'-'Z' */
#define _ACPI_XD     0x80    /* '0'-'9', 'A'-'F', 'a'-'f' */

#define isdigit(c)  (acpi_gbl_ctypes[(unsigned char)(c)] & (_ACPI_DI))
#define isspace(c)  (acpi_gbl_ctypes[(unsigned char)(c)] & (_ACPI_SP))
#define isxdigit(c) (acpi_gbl_ctypes[(unsigned char)(c)] & (_ACPI_XD))
#define isupper(c)  (acpi_gbl_ctypes[(unsigned char)(c)] & (_ACPI_UP))
#define islower(c)  (acpi_gbl_ctypes[(unsigned char)(c)] & (_ACPI_LO))
#define isprint(c)  (acpi_gbl_ctypes[(unsigned char)(c)] & (_ACPI_LO | _ACPI_UP | _ACPI_DI | _ACPI_XS | _ACPI_PU))
#define isalpha(c)  (acpi_gbl_ctypes[(unsigned char)(c)] & (_ACPI_LO | _ACPI_UP))

/* Error code */

#define EPERM            1 /* Operation not permitted */
#define ENOENT           2 /* No such file or directory */
#define EINTR            4 /* Interrupted system call */
#define EIO              5 /* I/O error */
#define EBADF            9 /* Bad file number */
#define EAGAIN          11 /* Try again */
#define ENOMEM          12 /* Out of memory */
#define EACCES          13 /* Permission denied */
#define EFAULT          14 /* Bad address */
#define EBUSY           16 /* Device or resource busy */
#define EEXIST          17 /* File exists */
#define ENODEV          19 /* No such device */
#define EINVAL          22 /* Invalid argument */
#define EPIPE           32 /* Broken pipe */
#define ERANGE          34 /* Math result not representable */

/* Strings */

char *
strcat (
	char                            *dst_string,
	const char                      *src_string);

char *
strchr (
	const char                      *string,
	int                             ch);

char *
strpbrk (
	const char                      *string,
	const char                      *delimiters);

char *
strtok (
	char                            *string,
	const char                      *delimiters);

char *
strcpy (
	char                            *dst_string,
	const char                      *src_string);

int
strcmp (
	const char                      *string1,
	const char                      *string2);

acpi_size
strlen (
	const char                      *string);

char *
strncat (
	char                            *dst_string,
	const char                      *src_string,
	acpi_size                       count);

int
strncmp (
	const char                      *string1,
	const char                      *string2,
	acpi_size                       count);

char *
strncpy (
	char                            *dst_string,
	const char                      *src_string,
	acpi_size                       count);

char *
strstr (
	char                            *string1,
	char                            *string2);


/* Conversion */

u32
strtoul (
	const char                      *string,
	char                            **terminator,
	u32                             base);


/* Memory */

int
memcmp (
	void                            *buffer1,
	void                            *buffer2,
	acpi_size                       count);

void *
memcpy (
	void                            *dest,
	const void                      *src,
	acpi_size                       count);

void *
memmove (
	void                            *dest,
	const void                      *src,
	acpi_size                       count);

void *
memset (
	void                            *dest,
	int                             value,
	acpi_size                       count);


/* upper/lower case */

int
tolower (
	int                             c);

int
toupper (
	int                             c);

/*
 * utprint - printf/vprintf output functions
 */
const char *
acpi_ut_scan_number (
	const char                      *string,
	u64                             *number_ptr);

const char *
acpi_ut_print_number (
	char                            *string,
	u64                             number);

int
vsnprintf (
	char                            *string,
	acpi_size                       size,
	const char                      *format,
	va_list                 args);

int
snprintf (
	char                            *string,
	acpi_size                       size,
	const char                      *format,
	...);

int
sprintf (
	char                            *string,
	const char                      *format,
	...);

#ifdef ACPI_APPLICATION
#define SEEK_SET            0
#define SEEK_CUR            1
#define SEEK_END            2

/*
 * NOTE: Currently we only need to update errno for file IOs. Other
 *       Clibrary invocations in ACPICA do not make decisions according to
 *       the errno.
 */
extern int errno;

#ifndef EOF
#define EOF                 (-1)
#endif

#define putchar(c)          fputc(stdout, c)
#define getchar(c)          fgetc(stdin)

int
vprintf (
	const char                      *format,
	va_list                 args);

int
printf (
	const char                      *format,
	...);

int
vfprintf (
	FILE                            *file,
	const char                      *format,
	va_list                 args);

int
fprintf (
	FILE                            *file,
	const char                      *format,
	...);

FILE *
fopen (
	const char                      *path,
	const char                      *modes);

void
fclose (
	FILE                            *file);

int
fread (
	void                            *buffer,
	acpi_size                       size,
	acpi_size                       count,
	FILE                            *file);

int
fwrite (
	void                            *buffer,
	acpi_size                       size,
	acpi_size                       count,
	FILE                            *file);

int
fseek (
	FILE                            *file,
	long                    offset,
	int                             from);

long
ftell (
	FILE                            *file);

int
fgetc (
	FILE                            *file);

int
fputc (
	FILE                            *file,
	char                            c);

char *
fgets (
	char                            *s,
	acpi_size                       size,
	FILE                            *file);
#endif

#endif /* _ACCLIB_H */
