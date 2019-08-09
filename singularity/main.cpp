/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <iostream>

#include <sys/socket.h>
#include <wserver_public_api.h>

int main(int argc, char **argv, char **envp)
{
	int status = wserver_connect();

	if(status < 0)
	{
		std::cout << "Error: wserver_connect() failed\n";
		return 1;
	}

	std::cout << "singularity started!\n";

	server_message_create_window params;
	params.height = 1024;
	params.width = 768;
	params.x = 0;
	params.y = 0;
	WINDOW win = wserver_create_window(&params);
	if(win == BAD_WINDOW)
	{
		std::cerr << "Error: wserver_create_window failed\n";
		perror("");
		return 1;
	}

	return 0;
}