/*
* Copyright (c) 2021 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <cstdio>
#include <cstring>
#include <string>
#include <getopt.h>
#include <unistd.h>

#include <options.h>
#include <object.h>

void print_usage()
{
	std::printf("Usage: ip [OPTIONS] OBJECT { COMMAND | HELP }\n"
	            "where\tOBJECT := {link | address | route | help}\n"
				"and \tOPTIONS := {-h[elp] | -V[ersion] | -json | -f[amily] {inet | inet6 | link} |\n"
				"\t-4 | -6 | -0 | -c[olor]}\n");
}

void print_version()
{
	std::printf("iptools version 20200510\n");
}

static int option_json = 0;
static int option_color = 0;
static int option_pretty = 0;

static family fam = family::all;

bool is_family_option_enabled(family fam_)
{
	return fam == family::all || fam == fam_;
}

bool is_color_enabled()
{
	// Only enable color if the display mode isn't json!
	return option_color && get_display_mode() == display_mode::normal;
}

display_mode get_display_mode()
{
	if(option_json)
		return display_mode::json;
	
	if(option_pretty)
		return display_mode::pretty_json;
	
	return display_mode::normal;
}

struct option options[] = 
{
	{"Version", no_argument, nullptr, 'V'},
	{"help", no_argument, nullptr, 'h'},
	{"json", no_argument, &option_json, 1},
	{"family", required_argument, nullptr, 'f'},
	{"color", no_argument, &option_color, 1},
	{"pretty", no_argument, &option_pretty, 1}
};

static bool parse_family(char *arg)
{
	if(!strcmp(arg, "inet"))
	{
		fam = family::inet;
	}
	else if(!strcmp(arg, "inet6"))
	{
		fam = family::inet6;
	}
	else if(!strcmp(arg, "link"))
	{
		fam = family::link;
	}
	else
	{
		std::printf("Error: invalid protocol family %s\n", arg);
		return false;
	}

	return true;
}

object *find_object(const std::string& name);

int main(int argc, char **argv)
{
	if(argc < 2)
	{
		print_usage();	
		return 1;
	}

	int optindex = 0;
	int opt;
	while((opt = getopt_long_only(argc, argv, "Vh460f:jpc", options, &optindex)) != -1)
	{
		switch(opt)
		{
			case 'V':
				print_version();
				return 0;
			case 'h':
			case '?':
				print_usage();
				return opt == '?';
			case '4':
				fam = family::inet;
				break;
			case '6':
				fam = family::inet6;
				break;
			case '0':
				fam = family::link;
				break;
			case 'f':
				if(!parse_family(optarg))
					return 1;
				break;
			case 'j':
				option_json = 1;
				break;
			case 'p':
				option_pretty = 1;
				break;
			case 'c':
				option_color = 1;
				break;
		}
	}

	if(option_pretty && !option_json)
		option_pretty = 0;
	
	// TODO: add =always,auto,never support
	if(option_color && !isatty(STDOUT_FILENO))
		option_color = 0;

	// Usage error: we need the object part of the command
	if(optind == argc)
	{
		print_usage();
		return 1;
	}

	std::string object_name{argv[optind]};

	auto object = find_object(object_name);

	if(!object)
	{
		std::printf("Object \"%s\" unknown, try \"ip help\"\n", object_name.c_str());
		return 1;
	}

	// Discard the arguments before optind, including the object name itself

	return object->handle((const char **) argv + optind + 1, argc - optind - 1);
}

// Here's the object list, add the objects in the order of priorities.
// The order inside the array disambiguates between objects in case of ambiguity,
// like 'a' matching 'address' and 'aahhhhhhhhhhahah'.
//extern object *address_obj;
extern object *link_obj;

object *objects[] = 
{
	//address_obj,
	link_obj
};

object *find_object(const std::string& name)
{
	for(const auto &obj : objects)
	{
		if(obj->get_name().starts_with(name))
			return obj;
	}

	return nullptr;
}
