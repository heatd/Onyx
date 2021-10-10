/*
* Copyright (c) 2021 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <iostream>
#include <unistd.h>

#include <getopt.h>

#include <filesystem.h>
#include <commands.h>

#include <sys/stat.h>

const struct option long_options[] =
{ 
	{"help", 0, nullptr, 'h'},
	{"version", 0, nullptr, 'v'},
	{"user", 0, nullptr, 'u'},
	{"root", 1, nullptr, 'r'},
	{},
};

void show_help(int flag)
{
	/* Return 1 if it was an invalid flag. */
	int ret = flag == '?';

	printf("Usage:\n   pkgman [options] [command] [...]\nOptions:\n"
	       "   -h/--help     Print help and exit\n"
		   "   -v            Print version and exit\n"
		   "   -u/--user            Install as user\n"
		   "   --root=[root]        Specify the filesystem root\n");

	printf("Valid commands:\n"
	        "   install       Installs a package\n"
			"   list          Lists installed packages\n"
			"   query         Gets metadata about a specific package\n");	
	std::exit(ret);
}

void show_version()
{
	printf("Onyx pkgman from 29032021\n");
	std::exit(0);
}

namespace pkgman
{

bool install_user = false;
std::string filesystem_prefix;

const std::string& get_sysroot()
{
	return filesystem_prefix;
}

}

int main(int argc, char **argv)
{
	int indexptr = 0;
	int flag = 0;
	while((flag = getopt_long(argc, argv, "huv", long_options, &indexptr)) != -1)
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
			case 'u':
				pkgman::install_user = true;
				break;
			case 'r':
				pkgman::filesystem_prefix = std::string(optarg);
				break;
		}
	}

	if(optind == argc)
	{
		show_help('?');
	}

	if(pkgman::filesystem_prefix.length() != 0 && !pkgman::file_exists(pkgman::filesystem_prefix))
	{
		std::cerr << "Error: System root " << pkgman::filesystem_prefix << " does not exist!\n";
		return 1;
	}

	std::string command = argv[optind++];

	if(command == "install")
	{
		return pkgman::commands::install(argv, optind);
	}
	else if(command == "list")
	{
		return pkgman::commands::list(argv, optind);
	}
	else if(command == "query")
	{
		return pkgman::commands::query(argv, optind);
	}

	return 0;
}
