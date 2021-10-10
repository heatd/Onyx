/*
* Copyright (c) 2021 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <cassert>

#include <object.h>

int object::handle(const char **args, int argc)
{
	auto commands = get_commands();
	auto default_command = get_default_command();

	assert(commands.data() != nullptr);
	assert(default_command != nullptr);

	const char *name = default_command;

	if(argc > 0)
	{
		name = args[0];
		args++;
		argc--;
	}

	command *to_execute = nullptr;

	for(auto &c : commands)
	{
		if(c.name.starts_with(name))
		{
			to_execute = &c;
			break;
		}
	}

	if(!to_execute)
	{
		std::printf("Command \"%s\" is unknown, try \"ip %s help\".", name, this->name.c_str());
		return 1;
	}

	return to_execute->handle(args, argc);
}
