/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_FILE_H
#define _ONYX_FILE_H

#include <fcntl.h>
#include <errno.h>

#include <onyx/vfs.h>
#include <onyx/panic.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ioctx;

void file_do_cloexec(struct ioctx *ctx);
int open_with_vnode(struct file *node, int flags);
struct file *get_file_description(int fd);
void fd_get(struct file *fd);
void fd_put(struct file *fd);
int allocate_file_descriptor_table(struct process *process);
int copy_file_descriptors(struct process *process, struct ioctx *ctx);
struct file *get_dirfd_file(int dirfd);

#define OPEN_FLAGS_ACCESS_MODE(flags)	(flags & 0x3)

static inline unsigned int open_to_file_access_flags(int open_flgs)
{
	unsigned int last_two_bits = OPEN_FLAGS_ACCESS_MODE(open_flgs);
	if(last_two_bits == O_RDONLY)
		return FILE_ACCESS_READ;
	else if(last_two_bits == O_RDWR)
		return FILE_ACCESS_READ | FILE_ACCESS_WRITE;
	else if(last_two_bits == O_WRONLY)
		return FILE_ACCESS_WRITE;
	else
	{
		panic("Unsanitized open flags");
	}
}

bool fd_may_access(struct file *f, unsigned int access);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

class auto_file
{
private:
	struct file *f;

	void ref() const
	{
		if(f) fd_get(f);
	}

	void unref() const
	{
		if(f) fd_put(f);
	}

public:

	auto_file() : f{nullptr}
	{
		
	}

	auto_file(file *_f) : f{_f} {}

	~auto_file()
	{
		if(f) fd_put(f);
	}

	auto_file& operator=(const auto_file& rhs)
	{
		if(&rhs == this)
			return *this;
		
		unref();

		if(rhs.f)
		{
			rhs.ref();
			f = rhs.f;
		}

		return *this;
	}

	auto_file(const auto_file& rhs)
	{
		if(&rhs == this)
			return;
		
		unref();

		if(rhs.f)
		{
			rhs.ref();
			f = rhs.f;
		}
	}

	auto_file& operator=(auto_file&& rhs)
	{
		if(&rhs == this)
			return *this;
		
		f = rhs.f;
		rhs.f = nullptr;

		return *this;
	}

	auto_file(auto_file&& rhs)
	{
		if(&rhs == this)
			return;
		
		f = rhs.f;
		rhs.f = nullptr;
	}

	file *get_file()
	{
		return f;
	}

	file *release()
	{
		auto ret = f;
		f = nullptr;
		return ret;
	}

	int from_fd(int fd)
	{
		f = get_file_description(fd);
		if(!f)
			return -errno;
		return 0;
	}

	int from_dirfd(int dirfd)
	{
		f = get_dirfd_file(dirfd);
		if(!f)
			return -errno;
		return 0;
	}

	operator bool() const
	{
		return f != nullptr;
	}

	bool is_dir() const
	{
		return f->f_ino->i_type == VFS_TYPE_DIR;
	}
};

template <typename Type>
bool is_absolute_pathname(const Type& t)
{
	return t[0] == '/';
}

#endif

#endif
