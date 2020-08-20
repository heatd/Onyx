/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

void print_help()
{
	printf("sleep - sleeps for n time units, where they may be a suffix 's'"
	       "for seconds, 'm' for minutes, 'h' for hours and 'd' for days\n");
	printf("The default time unit is seconds.\n");
}

void print_version()
{
	printf("sleep - Onyx coreutils 0.4\n");
}

#define SECS_PER_MIN		60
#define SECS_PER_HOUR		3600
#define SECS_PER_DAY		86400

void do_sleep(const char *arg)
{
	char unit_char;
	unsigned int timeunits;
	unsigned int seconds = 0;

	int ret = sscanf(arg, "%u%c", &timeunits, unit_char);
	if(ret == EOF || ret == 0)
	{
		print_help();
		return;
	}

	/* Perform unit conversion */
	if(unit_char == 's' || ret == 1)
	{
		seconds = timeunits;
	}
	else if(unit_char == 'm')
	{
		seconds = timeunits * SECS_PER_MIN;
	}
	else if(unit_char == 'h')
	{
		seconds = timeunits * SECS_PER_HOUR;
	}
	else if(unit_char == 'd')
	{
		seconds = timeunits * SECS_PER_DAY;
	}
	else
	{
		printf("sleep - invalid time suffix\n");
		print_help();
		return;
	}

	sleep(seconds);
}

int main(int argc, char **argv)
{
	if(argc < 2)
	{
		print_help();
		return 0;
	}

	const char *arg = argv[1];
	if(!isdigit(*arg))
	{
		if(arg[1] == 'v')
			print_version();
		else if(arg[1] == 'h')
			print_help();
		else
		{
			printf("Unrecognized option %c\n", arg[1]);
		}

		return 1;
	}
	else
		do_sleep(arg);
}