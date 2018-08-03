/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <stdbool.h>
#include <fcntl.h>
#include <memory>
#include <iostream>

#include <display.h>
#include <window.h>
#include <server.h>

#include <drm/drm.h>

#include <sys/mman.h>

int main(int argc, char **argv, char **envp)
{
	printf("wserver - window server\n");
	
	try
	{
		std::shared_ptr<Display> disp = std::make_shared<Display>();
		Server server(disp);	
	}
	catch(const std::exception& e)
	{
		std::cerr << e.what() << '\n';
		perror("errno value");
		return 1;
	}

	while(true)
	{
	}


	return 0;
}
