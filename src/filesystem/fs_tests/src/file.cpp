/*
* Copyright (c) 2021 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <unistd.h>
#include <fcntl.h>
#include <array>

#include <gtest/gtest.h>

#include <sys/mman.h>

extern "C"
{

#include <onyx/crypt/sha256.h>

}

#include "temp_file.hpp"

__attribute__((constructor))
void set_cwd()
{
	auto test_root = getenv("FSTEST_ROOT");
	if(!test_root)
		return;
	
	if(chdir(test_root) < 0)
		throw std::runtime_error("Could not change directory");
}

void WriteSingleSize(size_t size)
{
	std::string file_name = "file-test-";
	file_name.append("-");
	file_name.append(std::to_string(size));
	file_name.append("-XXXXXX");

	temp_file f{file_name};
	int fd = f.get_fd();

	sha256_state st0, st1;
	std::array<unsigned char, 32> key0, key1;

	sha256_init(&st0);
	sha256_init(&st1);

	std::array<unsigned char, 16> pattern{0xfe, 0xff, 0x53, 0x75, 0x87, 0x99, 0x78, 0xe4,
	                                     0xee, 0xeb, 0xb1, 0x12, 0x00, 0xd, 0x66, 0xab};
	
	auto iters = size / pattern.size();

	std::cout << "Size " << size << " ";

	for(unsigned int i = 0; i < iters; i++)
	{
		ASSERT_EQ(write(fd, pattern.data(), pattern.size()), (ssize_t) pattern.size());
		ASSERT_EQ(sha256_process(&st1,
		                        static_cast<const unsigned char*>(pattern.data()),
								pattern.size()), 0);
	}

	f.sync();

	off_t len = lseek(fd, 0, SEEK_CUR);

	const void *ptr = mmap(nullptr, len, PROT_READ, MAP_SHARED, fd, 0);
	ASSERT_NE(ptr, MAP_FAILED);

	ASSERT_EQ(sha256_process(&st0, static_cast<const unsigned char *>(ptr), len), 0);

	ASSERT_EQ(sha256_done(&st0, key0.data()), 0);
	ASSERT_EQ(sha256_done(&st1, key1.data()), 0);

	ASSERT_EQ(key0, key1);

	munmap((void *) ptr, len);

	std::cout << "Hash: ";
	for(auto &b : key0)
		std::cout << std::hex << (unsigned int) b << std::dec;

	std::cout << "\n";
	f.dont_delete();
}

TEST(FsTest, WriteMultSizes)
{
	for(unsigned long n = 10; n < 26; n++)
	{
		auto size = 1 << n;

		WriteSingleSize(size);
	}
}

#if 0
TEST(FsTest, WriteSeq)
{
	temp_file f;
	int fd = f.get_fd();

	sha256_state st0, st1;
	std::array<unsigned char, 32> key0, key1;

	sha256_init(&st0);
	sha256_init(&st1);

	std::array<unsigned char, 16> pattern{0xfe, 0xff, 0x53, 0x75, 0x87, 0x99, 0x78, 0xe4,
	                                     0xee, 0xeb, 0xb1, 0x12, 0x00, 0xd, 0x66, 0xab};

	for(unsigned int i = 0; i < 2000000; i++)
	{
		ASSERT_EQ(write(fd, pattern.data(), pattern.size()), (ssize_t) pattern.size());
		ASSERT_EQ(sha256_process(&st1,
		                        static_cast<const unsigned char*>(pattern.data()),
								pattern.size()), 0);
	}

	f.sync();

	off_t len = lseek(fd, 0, SEEK_CUR);

	const void *ptr = mmap(nullptr, len, PROT_READ, MAP_SHARED, fd, 0);
	ASSERT_NE(ptr, MAP_FAILED);

	ASSERT_EQ(sha256_process(&st0, static_cast<const unsigned char *>(ptr), len), 0);

	ASSERT_EQ(sha256_done(&st0, key0.data()), 0);
	ASSERT_EQ(sha256_done(&st1, key1.data()), 0);

	ASSERT_EQ(key0, key1);

	munmap((void *) ptr, len);

	std::cout << "Hash: ";
	for(auto &b : key0)
		std::cout << std::hex << (unsigned int) b;

	std::cout << "\n";
	f.dont_delete();
}
#endif

void CreateOne(size_t instance) {
	std::string file_name = "file-test-";
	file_name.append("-");
	file_name.append(std::to_string(instance));
	file_name.append("-XXXXXX");
	auto size = 4096 * 32;

	temp_file f{file_name};
	struct stat buf;

	ASSERT_EQ(::stat(f.get_file_name(), &buf), 0);
	int fd = f.get_fd();

	sha256_state st0, st1;
	std::array<unsigned char, 32> key0, key1;

	sha256_init(&st0);
	sha256_init(&st1);

	std::array<unsigned char, 16> pattern{0xfe, 0xff, 0x53, 0x75, 0x87, 0x99, 0x78, 0xe4,
	                                     0xee, 0xeb, 0xb1, 0x12, 0x00, 0xd, 0x66, 0xab};
	
	auto iters = size / pattern.size();

	for(unsigned int i = 0; i < iters; i++)
	{
		ASSERT_EQ(write(fd, pattern.data(), pattern.size()), (ssize_t) pattern.size());
		ASSERT_EQ(sha256_process(&st1,
		                        static_cast<const unsigned char*>(pattern.data()),
								pattern.size()), 0);
	}

	f.sync();

	off_t len = lseek(fd, 0, SEEK_CUR);

	const void *ptr = mmap(nullptr, len, PROT_READ, MAP_SHARED, fd, 0);
	ASSERT_NE(ptr, MAP_FAILED);

	ASSERT_EQ(sha256_process(&st0, static_cast<const unsigned char *>(ptr), len), 0);

	ASSERT_EQ(sha256_done(&st0, key0.data()), 0);
	ASSERT_EQ(sha256_done(&st1, key1.data()), 0);

	ASSERT_EQ(key0, key1);

	munmap((void *) ptr, len);
}

TEST(FsTest, CreateLotsDeleteLots) {

	for(unsigned int i = 0; i < 1000; i++)
	{
		CreateOne(i);
	}
}
