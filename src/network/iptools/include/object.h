/*
* Copyright (c) 2021 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <string>
#include <span>

struct command
{
	std::string name;
	int (*handle)(const char **, int);
};

/**
 * @brief Represents an object inside the 'ip' tool.
 * Examples include 'address', 'link', 'route', etc.
 * 
 */
class object
{
private:
	std::string name;
public:
	object(std::string name) : name{name}{}

	// Note: Returns by reference, but it shouldn't be an issue here.
	const std::string& get_name() const
	{
		return name;
	}

	virtual std::span<command> get_commands() const
	{
		return {};
	}

	virtual const char *get_default_command() const
	{
		return "show";
	}

	virtual int handle(const char **args, int argc);
};
