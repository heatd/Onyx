/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>

#include <sys/utsname.h>

bool print_os_name = false;
bool hardware_type = false;
bool node = false;
bool release = false;
bool current_version = false;

void invalid_flag()
{
	printf("Usage: uname  [-amnsv]\n");
}

int main(int argc, char **argv, char **envp)
{
	if(argc < 2)
		print_os_name = true;
	int chr;
	while((chr = getopt(argc, argv, "amnrsv")) != -1)
	{
		switch(chr)
		{
			case 'a':
			{
				print_os_name = true;
				hardware_type = true;
				node = true;
				release = true;
				current_version = true;
				break;
			}
			case 'm':
			{
				hardware_type = true;
				break;
			}
			case 'n':
			{
				node = true;
				break;
			}
			case 'r':
			{
				release = true;
				break;
			}
			case 's':
			{
				print_os_name = true;
				break;
			}
			case 'v':
			{
				current_version = true;
				break;
			}
			default:
				invalid_flag();
		}
	}

	struct utsname info;
	if(uname(&info) < 0)
	{
		perror("uname");
		return 1;
	}

	if(print_os_name)
		printf("%s ", info.sysname);
	if(node)
		printf("%s ", info.nodename);
	if(release)
		printf("%s ", info.release);
	if(current_version)
		printf("%s ", info.version);
	if(hardware_type)
		printf("%s ", info.machine);
	printf("\n");

	return 0;
}
