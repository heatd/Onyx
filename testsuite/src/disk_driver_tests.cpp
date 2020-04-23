/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
*/

#include <stdbool.h>
#include <unistd.h>
#include <thread>
#include <vector>
#include <fcntl.h>
#include <iostream>
#include <mutex>

#include <test/libtest.h>

bool disk_test()
{
	std::vector<std::thread> thread_vector;

	for(int i = 0; i < 4; i++)
	{
		thread_vector.push_back(std::thread([]()
		{
			int fd = open("/dev/sda", O_RDONLY);
			if(fd < 0)
			{
				perror("open");
				throw std::runtime_error("Open failed");
			}

			struct timespec ts;
			clock_gettime(CLOCK_MONOTONIC, &ts);

			while(true)
			{
				unsigned char buffer[4096];
				if(lseek(fd, 0, SEEK_SET) < 0)
				{
					perror("lseek");
					throw std::runtime_error("lseek failed");
				}
			
				int st = read(fd, &buffer, sizeof(buffer));

				if(st < 0)
				{
					perror("read");
					throw std::runtime_error("read failed");
				}

				struct timespec ts1;
				clock_gettime(CLOCK_MONOTONIC, &ts1);

				if(ts1.tv_sec - ts.tv_sec >= 60)
					return;
			}
		}));
	}

	for(auto &t : thread_vector)
	{
		t.join();
	}

	std::cout << "Test done.\n";
	return true;
}

DECLARE_TEST(disk_test, 2);
