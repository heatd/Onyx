/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
*/
#include <thread>
#include <array>
#include <unistd.h>
#include <fcntl.h>
#include <cstdlib>

#include <sys/mman.h>

#ifndef __linux__
#include <test/libtest.h>
#endif

static int created_fd = -1;

static void mmap_test_shared()
{

}

static void mmap_test_private()
{

}

static bool mmap_test()
{
	char template_file[] = "mmap_test-XXXXXX";

	/* First, create a new file to be used as mmap bait */
	created_fd = mkstemp(template_file);

	if(created_fd < 0)
	{
		perror("mkstemp");
		return false;
	}

	unlink(template_file);

	/* Give it some size */
	if(ftruncate(created_fd, 4096 * 16) < 0)
	{
		perror("ftruncate");
		return false;
	}

	std::thread t0{mmap_test_shared};
	std::thread t1{mmap_test_private};

	t0.join();
	t1.join();

	return true;
}

#ifdef __linux__

int main()
{
	for(int i = 0; i < 5; i++)
		mmap_test();
}

#else

DECLARE_TEST(mmap_test, 5);

#endif
