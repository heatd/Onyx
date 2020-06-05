/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_PHOTON_H
#define _ONYX_PHOTON_H

#include <onyx/object.h>
#include <onyx/framebuffer.h>
#include <onyx/spinlock.h>
#include <onyx/rbtree.hpp>
#include <onyx/memory.hpp>
#include <onyx/vector.h>
#include <onyx/list.hpp>
#include <onyx/photon-cookies.h>
#include <onyx/expected.hpp>
#include <onyx/atomic.hpp>
#include <onyx/scoped_lock.h>

#include <photon/photon.h>


namespace photon
{

class device;

#define PHOTON_OBJECT_NAMED               (1 << 0)

class object
{
	friend class device;
	device *dev;
	unsigned long object_cookie;
	unsigned long flags;
	uint32_t name;
	/* Security cookie set by user space as to disallow access by random processes */
	/* TODO: Maybe this isn't safe? It's 64-bit now so it should be relatively safe from
	 * bruteforce but I don't think it's the right approach */
	uint64_t security_cookie;
	list_head_cpp<object> named_list;
public:
	object(device *dev, unsigned long cookie) : dev{dev}, object_cookie{cookie},
	              flags{}, name{}, security_cookie{}, named_list{this}
	{}

	void remove_from_named_list();

	virtual ~object()
	{
		if(flags & PHOTON_OBJECT_NAMED)
		{
			remove_from_named_list();
		}
	}

	constexpr bool is_buffer() const
	{
		if(object_cookie == PHOTON_COOKIE_DUMB_BUFFER)
			return true;
		return false;
	}
};

class dumb_buffer : public photon::object
{
	void *buffer;
	page *pages;
	size_t size;
public:
	dumb_buffer(device *dev) : object(dev, PHOTON_COOKIE_DUMB_BUFFER) {}

	void *get_buffer() const
	{
		return buffer;
	}

	struct page *get_pages() const
	{
		return pages;
	}

	size_t get_size() const
	{
		return size;
	}
};

class mapping : public object
{
	off_t fake_offset;
	shared_ptr<object> buffer;
public:
	mapping(device *dev, shared_ptr<object> buf) : object(dev, PHOTON_COOKIE_MAPPING),
	      buffer{buf} {}

	void set_fake_off(off_t off)
	{
		fake_offset = off;
	}

	off_t fake_off() const
	{
		return fake_offset;
	}

	shared_ptr<object> buf()
	{
		return buffer;
	}
};

class context
{
	friend class device;
	pid_t pid;
	cul::vector<shared_ptr<object>> handle_table;
	spinlock handle_table_lock;
	atomic<off_t> curr_fake_offset;
	spinlock mappings_lock;
	linked_list<shared_ptr<mapping>> mapping_list;
public:
	context(pid_t pid) : pid{pid}, handle_table{}, handle_table_lock{},
                         curr_fake_offset{}, mappings_lock{}, mapping_list{}
	{}

	~context() = default;

	photon_handle add_object(const shared_ptr<object>& obj);
	shared_ptr<object> get_object(photon_handle handle);
	unsigned int close_object(photon_handle handle);
	bool append_mapping(shared_ptr<mapping> mapping);
	
	off_t allocate_fake_offset()
	{
		return curr_fake_offset.fetch_add(PAGE_SIZE);
	}

	expected<off_t, int> create_buffer_mapping(shared_ptr<object> obj, device *dev);
	bool add_mapping(shared_ptr<mapping> obj)
	{
		scoped_lock g{&mappings_lock};
		return mapping_list.add(obj);
	}

	shared_ptr<mapping> get_mapping(off_t offset);
};

class device
{
protected:
	const char *name;
	::dev *dev;
	const char *driver_info;

	spinlock named_list_lock;
	list_head named_list;
	atomic<uint32_t> current_name;

	spinlock context_lock;
	cul::rb_tree<pid_t, shared_ptr<context>> context_list;
	int create_new_context(pid_t pid);
	shared_ptr<context> get_context(pid_t pid);

	virtual expected<shared_ptr<dumb_buffer>, int> dumb_create(photon_dumb_buffer_info& buffer) = 0;
	virtual int swap_buffers(object *buf) = 0;

	expected<uint32_t, bool> generate_name();

public:

	device()
	{
		INIT_LIST_HEAD(&named_list);
	}

	virtual ~device()
	{}

	virtual unsigned int handle_platform_ioctls(int req, void *argp)
	{
		return -ENOTTY;
	}

	shared_ptr<context> get_default_context();

	photon_handle add_object(const shared_ptr<object>& obj, shared_ptr<context> ctx = nullptr);
	shared_ptr<object> get_object(photon_handle handle, shared_ptr<context> ctx = nullptr);
	unsigned int close_object(photon_handle handle, shared_ptr<context> ctx = nullptr);
	void remove_object_from_named_list(object *obj);
	expected<cul::pair<object *, scoped_lock<spinlock>>, bool> get_object_from_name(uint32_t name);
	int on_open();

	int do_create_dumb_buffer(photon_dumb_buffer_info& info);
	int do_swap_buffers(const photon_swap_buffer_args& args);
	off_t do_enable_buffer_mappings(photon_handle handle);
	unsigned int do_ioctl_set_name(photon_set_name_args *uargs);
	unsigned int do_ioctl_open_from_name(photon_open_from_name_args *uargs);
	unsigned int do_ioctl_close_handle(photon_close_handle_args *uargs);
	unsigned int do_ioctls(int request, void *argp);
	void *do_mmap(struct vm_region *area, struct file *f);

	void set_dev(::dev *d)
	{
		dev = d;
	}
};


int add_device(photon::device *device);

inline device *photon_dev_from_file(struct file *f)
{
	return static_cast<device *>(f->f_ino->i_helper);
}

};

#endif
