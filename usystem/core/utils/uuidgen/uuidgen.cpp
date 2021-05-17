/*
* Copyright (c) 2021 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <cstdio>
#include <cstdlib>
#include <getopt.h>

#include <uuid/uuid.h>

enum uuid_type
{
	UUID_RANDOM = 0,
	UUID_TIME = 1
};

const struct option long_options[] =
{ 
	{"help", 0, nullptr, 'h'},
	{"version", 0, nullptr, 'v'},
	{"time", 0, nullptr, 't'},
	{}
};

void show_help(int flag)
{
	/* Return 1 if it was an invalid flag. */
	int ret = flag == '?';

	std::printf("Usage:\n   uuidgen [options]\nOptions:\n"
	       "   -h/--help     print help and exit\n"
		   "   -v/--version  print version and exit\n"
		   "   -t/--time     generate a time-based UUID\n"
		   "   -r/--random   generate a random-based UUID(default)\n");
	
	std::exit(ret);
}

void show_version()
{
	std::printf("Onyx uuidgen from Onyx utils 27042021\n");
	std::exit(0);
}

uuid_type type = UUID_RANDOM;

int main(int argc, char **argv, char **envp)
{
	int indexptr = 0;
	int flag = 0;
	while((flag = getopt_long(argc, argv, "vhtr", long_options, &indexptr)) != -1)
	{
		switch(flag)
		{
			case '?':
			case 'h':
				show_help(flag);
				break;
			case 'v':
				show_version();
				break;
			case 't':
				type = UUID_TIME;
				break;
			case 'r':
				type = UUID_RANDOM;
				break;
		}
	}

	uuid_t uuid;
	if(type == UUID_RANDOM)
	{
		uuid_generate_random(uuid);
	}
	else if(type == UUID_TIME)
	{
		uuid_generate_time(uuid);
	}

	char uuid_text[37];
	uuid_unparse(uuid, uuid_text);

	std::printf("%s\n", uuid_text);

	return 0;
}
