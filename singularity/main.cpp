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
	}

	return 0;
}