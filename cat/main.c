/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	printf("opening %s\n", argv[1]);
	FILE *file = fopen(argv[1], "r");
	if(fseek(file, 0L, SEEK_END) == -1)
		return 1;
	size_t file_size = ftell(file);
	printf("file_size: %u\n", file_size);
	rewind(file);
	char *buf = malloc(file_size);
	if(!buf)
		return 1;
	fread(buf, file_size, 1, file);
	printf("%s", buf);
	return 0;
}
