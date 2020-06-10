/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>
#include <stdio.h>
#include <errno.h>

#include <onyx/dentry.h>
#include <onyx/compiler.h>
#include <onyx/slab.h>
#include <onyx/atomic.h>
#include <onyx/vfs.h>
#include <onyx/file.h>
#include <onyx/mm/pool.hpp>
#include <onyx/mtable.h>
#include <onyx/string_view.hpp>
#include <onyx/expected.hpp>

static memory_pool<dentry, true> dentry_pool;
dentry *root_dentry = nullptr;

extern "C"
{

void dentry_get(dentry *d)
{
	/* Must hold parent's d_lock */
	__atomic_add_fetch(&d->d_ref, 1, __ATOMIC_RELAXED);
}

void dentry_put(dentry *d)
{
	if(__atomic_sub_fetch(&d->d_ref, 1, __ATOMIC_RELAXED) == 0)
		dentry_destroy(d);
}

}

enum class fs_token_type : uint8_t
{
	REGULAR_TOKEN = 0,
	LAST_NAME_IN_PATH
};

struct last_name_handling
{
	virtual expected<dentry *, int> operator()(nameidata& data, std::string_view &name) = 0;
};

struct nameidata
{
	/* Data needed to resolve filesystem names: 
	 * view - Contains the pathname;
	 * pos - Contains the offset in the parsing of the pathname;
	 * root - Contains the lookup's filesystem root;
	 * location - Contains the current relative location and
	 * starts at whatever was passed as the relative dir(controlled with
	 * chdir or *at, or purely through kernel-side use).
	 */
	std::string_view view;
	size_t pos;
	/* Note: root and location always hold a reference to the underlying object */
	dentry *root;
	dentry *location;
	fs_token_type token_type;

	static constexpr const size_t max_loops = SYMLOOP_MAX;
	/* Number of symbolic links found while looking up -
	 * if it reaches max_symlinks, the lookup fails with -ELOOP.
	 */
	int nloops;

	last_name_handling *handler;

	nameidata(std::string_view view, dentry *root, dentry *rel, last_name_handling *h = nullptr) :
	          view{view}, pos{}, root{root}, location{rel},
			  token_type{fs_token_type::REGULAR_TOKEN}, nloops{0}, handler{h}
	{}

	nameidata for_symlink_resolution(std::string_view path) const
	{
		nameidata n{path, root, location};
		if(root) dentry_get(root);
		if(location) dentry_get(location);
		n.nloops = nloops;

		return n;
	}

	/* Used after resolving a symlink in path resolution */
	void track_symlink_count(nameidata& d)
	{
		nloops = d.nloops;
	}
};

void dentry_destroy(dentry *d)
{
	if(d->d_inode) close_vfs(d->d_inode);
	if(d->d_parent) dentry_put(d->d_parent);
	if(d->d_name_length > INLINE_NAME_MAX)
	{
		free((void *) d->d_name);
	}
}

void dentry_kill_unlocked(dentry *entry)
{
	assert(entry->d_ref == 1);
	list_remove(&entry->d_parent_dir_node);
	dentry_destroy(entry);
}

extern "C" dentry *dentry_create(const char *name, inode *inode, dentry *parent)
{
	if(parent && parent->d_inode->i_type != VFS_TYPE_DIR)
		return errno = ENOTDIR, nullptr;

	dentry *new_dentry = dentry_pool.allocate();
	if(!new_dentry) [[unlikely]]
		return nullptr;
	memset(new_dentry, 0, sizeof(dentry));

	new_dentry->d_ref = 1;
	new_dentry->d_name = new_dentry->d_inline_name;
	
	size_t name_length = strlen(name);

	if(name_length <= INLINE_NAME_MAX)
	{
		strlcpy(new_dentry->d_name, name, INLINE_NAME_MAX);
	}
	else
	{
		char *dname = (char *) memdup((void *) name, name_length);
		if(!dname)
		{
			dentry_pool.free(new_dentry);
			return nullptr;
		}

		new_dentry->d_name = dname;
	}

	new_dentry->d_name_length = name_length;
	new_dentry->d_name_hash = fnv_hash(new_dentry->d_name, new_dentry->d_name_length);
	new_dentry->d_inode = inode;
	
	/* We need this if() because we might call dentry_create before retrieving an inode */
	if(inode) object_ref(&inode->i_object);
	new_dentry->d_parent = parent; 
	
	if(parent) [[likely]]
	{
		list_add_tail(&new_dentry->d_parent_dir_node, &parent->d_children_head);
		dentry_get(parent);
	}

	INIT_LIST_HEAD(&new_dentry->d_children_head);

	return new_dentry;
}

bool dentry_is_dir(dentry *d)
{
	return d->d_inode->i_type == VFS_TYPE_DIR;
}

dentry *__dentry_try_to_open(std::string_view name, dentry *dir)
{
	if(auto d = dentry_lookup_internal(name, dir,
	                 DENTRY_LOOKUP_UNLOCKED | DENTRY_LOOKUP_DONT_TRY_TO_RESOLVE))
		return d;

	//printk("trying to open %.*s in %s\n", (int) name.length(), name.data(), dir->d_name);

	char _name[NAME_MAX + 1] = {};
	memcpy(_name, name.data(), name.length());

	inode *ino = dir->d_inode->i_fops->open(dir, _name);
	if(!ino)
	{
		//printk("failed\n");
		return nullptr;
	}

	auto ret = dentry_create(_name, ino, dir);
	close_vfs(ino);

	if(ret)
	{
		dentry_get(ret);
		if(dentry_is_dir(ret)) ino->i_dentry = ret;
	}

	return ret;
}

dentry *dentry_try_to_open_locked(std::string_view name, dentry *dir)
{
	scoped_rwlock<rw_lock::write> g{dir->d_lock};
	return __dentry_try_to_open(name, dir);
}

dentry *dentry_parent(dentry *dir)
{
	scoped_rwlock<rw_lock::read> g{dir->d_lock};

	auto ret = dir->d_parent;
	
	if(ret) dentry_get(ret);

	return ret;
}

bool dentry_compare_name(dentry *dent, std::string_view& to_cmp)
{
	std::string_view dent_name{dent->d_name, dent->d_name_length};

	return dent_name.compare(to_cmp) == 0;
}

dentry *dentry_lookup_internal(std::string_view v, dentry *dir, dentry_lookup_flags_t flags)
{
	bool lock = !(flags & DENTRY_LOOKUP_UNLOCKED);
	bool resolve = !(flags & DENTRY_LOOKUP_DONT_TRY_TO_RESOLVE);

	fnv_hash_t hash = fnv_hash(v.data(), v.length());

	if(!v.compare("."))
	{
		dentry_get(dir);
		return dir;
	}

	if(!dentry_is_dir(dir))
	{
		return errno = ENOTDIR, nullptr;
	}

	if(lock) [[likely]]
		rw_lock_read(&dir->d_lock);

	if(!v.compare(".."))
	{
		auto ret = dir->d_parent ? dir->d_parent : dir;
		dentry_get(ret);
		if(lock) [[likely]] rw_unlock_read(&dir->d_lock);
		return ret;
	}

	list_for_every(&dir->d_children_head)
	{
		dentry *d = container_of(l, dentry, d_parent_dir_node);
		if(d->d_name_hash == hash && dentry_compare_name(d, v))
		{
			dentry_get(d);
			if(lock) [[likely]] rw_unlock_read(&dir->d_lock);
			return d;
		}
	}

	if(lock) [[likely]] rw_unlock_read(&dir->d_lock);
	return resolve ?
	      (lock ? dentry_try_to_open_locked(v, dir) : __dentry_try_to_open(v, dir))
		  : nullptr;
}

dentry *dentry_mount(const char *mountpoint, struct inode *inode)
{
	if(!strcmp(mountpoint, "/")) [[unlikely]]
	{
		/* shortpath: We're creating the absolute root inode */
		return (root_dentry = dentry_create(mountpoint, inode, nullptr));
	}

	char *path = strdup(mountpoint);
	if(!path)
		return nullptr;
	
	auto fs_root = get_filesystem_root();
	dentry_get(fs_root->file->f_dentry);
	std::string_view name{mountpoint, strlen(mountpoint)};
	nameidata namedata{name, fs_root->file->f_dentry, nullptr};

	auto base_dentry = dentry_resolve(namedata);
	if(!base_dentry)
	{
		free((void *) path);
		return nullptr;
	}

	if(!dentry_is_dir(base_dentry))
	{
		free((void *) path);
		dentry_put(base_dentry);
		errno = ENOTDIR;
		return nullptr;
	}

	dentry *new_d = dentry_create(basename(path), inode, base_dentry);

	if(new_d)
	{
		rw_lock_write(&base_dentry->d_lock);
		if(base_dentry->d_flags & DENTRY_FLAG_MOUNTPOINT)
		{
			rw_unlock_write(&base_dentry->d_lock);
			return errno = EBUSY, nullptr;
		}

		base_dentry->d_mount_dentry = new_d;
		base_dentry->d_flags |= DENTRY_FLAG_MOUNTPOINT;
		dentry_get(new_d);

		rw_unlock_write(&base_dentry->d_lock);
	}

	free((void *) path);
	dentry_put(base_dentry);

	return new_d;
}

extern "C" int mount_fs(struct inode *fsroot, const char *path)
{
	assert(fsroot != NULL);

	printf("mount_fs: Mounting on %s\n", path);
	
	if(!strcmp(path, "/"))
	{
		file *f = (file *) zalloc(sizeof(*f));
		if(!f)
			return -ENOMEM;
		f->f_ino = fsroot;
		f->f_refcount = 1;
		f->f_dentry = dentry_mount("/", fsroot);
		assert(f->f_dentry != nullptr);

		auto fs_root = get_filesystem_root();
		if(fs_root->file)
		{
			fd_put(fs_root->file);
		}

		fs_root->file = f;	
	}
	else
	{
		dentry *d;
		if(!(d = dentry_mount(path, fsroot)))
			return -errno;
		dentry_put(d);
	}

	return 0;
}

std::string_view get_token_from_path(nameidata& namedata)
{
	const auto &view = namedata.view;
	while(true)
	{
		namedata.pos = view.find_first_not_of('/', namedata.pos);
		if(namedata.pos == std::string_view::npos)
			break;

		auto path_elem_end = view.find('/', namedata.pos);
		//std::cout << "end at pos " << path_elem_end << "\n";
		//std::cout << "pos: " << pos << "\n";
		bool is_last_element = false;
		if(path_elem_end == std::string_view::npos) [[unlikely]]
		{
			is_last_element = true;
			path_elem_end = view.length();
		}
		else if(view.find_first_not_of('/', path_elem_end) == std::string_view::npos)
		{
			is_last_element = true;
		}

		namedata.token_type = is_last_element ?
		                      fs_token_type::LAST_NAME_IN_PATH : fs_token_type::REGULAR_TOKEN;

		//std::cout << "Elem size: " << path_elem_end - pos << "\n";
		std::string_view v = view.substr(namedata.pos, path_elem_end - namedata.pos);
		namedata.pos += v.length() + 1;
		//std::cout << "Path element: " << v << "\n";

		return v;
	}

	return {};
}

bool dentry_is_symlink(dentry *d)
{
	return d->d_inode->i_type == VFS_TYPE_SYMLINK;
}

bool dentry_check_for_existance(std::string_view name, dentry *d)
{
	dentry *res = nullptr;
	if((res = dentry_lookup_internal(name, d, DENTRY_LOOKUP_UNLOCKED)) == nullptr)
		return false;
	dentry_put(res);
	return true;
}

bool dentry_is_mountpoint(dentry *dir)
{
	return dir->d_flags & DENTRY_FLAG_MOUNTPOINT;
}

int __dentry_resolve_path(nameidata& data)
{
	std::string_view v;
	//printk("Resolving %s\n", data.view.data());

	while((v = get_token_from_path(data)).data() != nullptr)
	{
		if(v.length() > NAME_MAX)
			return -ENAMETOOLONG;
	
		//printk("%.*s\n", (int) v.length(), v.data());
		if(data.token_type == fs_token_type::LAST_NAME_IN_PATH && data.handler)
		{
			//printk("^^ is last name\n");
			auto ex = (*data.handler)(data, v);
			if(ex.has_value())
			{
				dentry_put(data.location);
				data.location = ex.value();
				dentry_get(data.location);
				return 0;
			}

			return ex.error();
		}

		file f;
		f.f_ino = data.location->d_inode;
		if(!file_can_access(&f, FILE_ACCESS_EXECUTE))
		{
			return -EACCES;
		}

		dentry *new_found = nullptr;
		if(data.location == data.root && !v.compare("..")) [[unlikely]]
		{
			/* Stop from escaping the chroot */
			continue;
		}
		else
		{
			new_found = dentry_lookup_internal(v, data.location);
			if(!new_found)
			{
				return -errno;
			}
		}
	
		if(dentry_is_symlink(new_found))
		{
			file f;
			f.f_ino = new_found->d_inode;

			/* Oops - We hit the max symlink count */
			if(data.nloops++ == data.max_loops)
			{
				dentry_put(new_found);
				return -ELOOP;
			}

			auto target_str = readlink_vfs(&f);
			if(!target_str)
			{
				dentry_put(new_found);
				return -errno;
			}

			/* Create a new nameidata for the new path, **with the current nloop**. 
			 * This makes it so we properly keep track of nloop.
			 */

			auto new_nameidata = data.for_symlink_resolution({target_str, strlen(target_str)});

			auto symlink_target = dentry_resolve(new_nameidata);

			free((void *) target_str);

			if(!symlink_target)
			{
				dentry_put(new_found);
				return -errno;
			}

			/* We need to track the new structure's nloop as to keep a lookup-global count */
			data.track_symlink_count(new_nameidata);

			dentry_put(new_found);
			new_found = symlink_target;
		}

		if(dentry_is_mountpoint(new_found))
		{
			auto dest = new_found->d_mount_dentry;
			dentry_put(new_found);
			new_found = dest;
		}

		dentry_put(data.location);
		data.location = new_found;
	}

	return 0;
}

int dentry_resolve_path(nameidata& data)
{
	auto &pathname = data.view;

	auto pathname_length = pathname.length();
	if(pathname_length == 0)
		return -ENOENT;

	//std::cout << "Total pathname: " << pathname << "\n";

	bool absolute = pathname[0] == '/';
	/*if(absolute)
		std::cout << "Pathname type: Absolute\n";
	else
		std::cout << "Pathname type: Relative\n";
	*/
	bool must_be_dir = pathname[pathname.length() - 1] == '/';

	std::string_view v;

	if(absolute)
	{
		if(data.location)
			dentry_put(data.location);
		data.location = data.root;
		dentry_get(data.root);
	}

	data.view = std::string_view(&pathname[(int) absolute], pathname_length - (int) absolute);

	auto st = __dentry_resolve_path(data);

	if(absolute)
	{
		dentry_put(data.root);
	}

	if(st < 0)
	{
		dentry_put(data.location);
		return st;
	}

	(void) must_be_dir;

	return 0;
}

dentry *dentry_resolve(nameidata& data)
{
	int st = dentry_resolve_path(data);
	if(st < 0)
		return errno = -st, nullptr;
	return data.location;
}

extern "C" file *open_vfs(file *f, const char *name)
{
	auto fs_root = get_filesystem_root();

	dentry_get(fs_root->file->f_dentry);
	dentry_get(f->f_dentry);

	nameidata namedata{std::string_view{name, strlen(name)},
					   fs_root->file->f_dentry, f->f_dentry};

	auto dent = dentry_resolve(namedata);

	if(!dent)
		return nullptr;

	auto new_file = inode_to_file(dent->d_inode);
	if(!new_file)
	{
		dentry_put(dent);
		return nullptr;
	}

	object_ref(&dent->d_inode->i_object);
	new_file->f_dentry = dent;

	return new_file;
}

void dentry_init(void) {}

enum class create_file_type
{
	creat,
	mknod,
	mkdir
};

struct create_file_info
{
	create_file_type type;
	mode_t mode;
	dev_t dev;
};

struct create_handling : public last_name_handling
{
	create_file_info in;
	create_handling(create_file_info info) : in{info} {}

	expected<dentry *, int> operator()(nameidata& data, std::string_view &name) override
	{
		//printk("Here.\n");
		auto dentry = data.location;
		auto inode = dentry->d_inode;

		char _name[NAME_MAX + 1] = {};
		memcpy(_name, name.data(), name.length());

		scoped_rwlock<rw_lock::write> g{dentry->d_lock};

		if(dentry_check_for_existance(name, dentry))
			return unexpected<int>{-EEXIST};
	
		auto new_dentry = dentry_create(_name, nullptr, dentry);
		if(!new_dentry)
			return unexpected<int>{-ENOMEM};

		struct inode *new_inode = nullptr;
	
		if(in.type == create_file_type::creat)
			new_inode = inode->i_fops->creat(_name, (int) in.mode, dentry);
		else if(in.type == create_file_type::mkdir)
			new_inode = inode->i_fops->mkdir(_name, in.mode, dentry);
		else if(in.type == create_file_type::mknod)
			new_inode = inode->i_fops->mknod(_name, in.mode, in.dev, dentry);

		if(!new_inode)
		{
			dentry_kill_unlocked(new_dentry);
			return unexpected<int>{-errno};
		}

		if(in.type == create_file_type::mkdir)
		{
			new_inode->i_dentry = new_dentry;
		}

		new_dentry->d_inode = new_inode;

		return new_dentry;
	}
};

struct symlink_handling : public last_name_handling
{
	const char *dest;
	symlink_handling(const char *d) : dest{d} {}

	expected<dentry *, int> operator()(nameidata& data, std::string_view &name) override
	{
		auto dentry = data.location;
		auto inode = dentry->d_inode;

		char _name[NAME_MAX + 1] = {};
		memcpy(_name, name.data(), name.length());

		scoped_rwlock<rw_lock::write> g{dentry->d_lock};

		if(dentry_check_for_existance(name, dentry))
			return unexpected<int>{-EEXIST};
	
		auto new_dentry = dentry_create(_name, nullptr, dentry);
		if(!new_dentry)
			return unexpected<int>{-ENOMEM};

		auto new_ino = inode->i_fops->symlink(_name, dest, dentry);

		if(!new_ino)
		{
			dentry_kill_unlocked(new_dentry);
			return unexpected<int>{-errno};
		}

		new_dentry->d_inode = new_ino;
		
		return new_dentry;
	}
};

file *file_creation_helper(dentry *base, const char *path, last_name_handling& h)
{
	auto fs_root = get_filesystem_root();

	dentry_get(fs_root->file->f_dentry);
	dentry_get(base);

	nameidata namedata{std::string_view{path, strlen(path)},
					   fs_root->file->f_dentry, base, &h};

	auto dent = dentry_resolve(namedata);

	if(!dent)
		return nullptr;

	auto new_file = inode_to_file(dent->d_inode);
	if(!new_file)
	{
		dentry_put(dent);
		return nullptr;
	}
	
	new_file->f_dentry = dent;

	return new_file;
}


extern "C"
{

file *creat_vfs(dentry *base, const char *path, int mode)
{
	create_handling h{{create_file_type::creat, (mode_t) mode, 0}};
	return file_creation_helper(base, path, h);
}

file *mknod_vfs(const char *path, mode_t mode, dev_t dev, struct dentry *dir)
{
	create_handling h{{create_file_type::mknod, mode, dev}};
	return file_creation_helper(dir, path, h);
}

file *mkdir_vfs(const char *path, mode_t mode, struct dentry *dir)
{
	create_handling h{{create_file_type::mkdir, mode, 0}};
	return file_creation_helper(dir, path, h);
}

struct file *symlink_vfs(const char *path, const char *dest, struct dentry *dir)
{
	symlink_handling h{dest};
	return file_creation_helper(dir, path, h);
}

struct path_element
{
	dentry *d;
	struct list_head node;
};

char *dentry_to_file_name(struct dentry *dentry)
{
	/* Calculate the initial length as / + the null terminator */
	size_t buf_len = 2;
	char *buf = nullptr;
	char *s = nullptr;
	auto fs_root = get_filesystem_root()->file->f_dentry;

	dentry_get(fs_root);

	auto d = dentry;
	struct list_head element_list;
	INIT_LIST_HEAD(&element_list);

	/* Get another ref here to have prettier code */
	dentry_get(d);

	/* TODO: Is this logic safe from race conditions? */
	while(d != fs_root && d != nullptr)
	{
		path_element *p = new path_element;
		if(!p)
			goto error;
		p->d = d;
		/* Add 1 to the len because of the separator */
		buf_len += d->d_name_length + 1;
		list_add(&p->node, &element_list);
		
		d = dentry_parent(d);
	}

	/* Remove one from the end to avoid trailing slashes */
	buf_len--;

	buf = (char *) malloc(buf_len);
	if(!buf)
		goto error;
	buf[0] = '/';
	s = &buf[1];
	
	list_for_every_safe(&element_list)
	{
		auto elem = container_of(l, struct path_element, node);
		auto dent = elem->d;
		memcpy(s, dent->d_name, dent->d_name_length);
		s += dent->d_name_length;
		*s++ = '/';
		dentry_put(dent);
		delete elem;
	}

	buf[buf_len - 1] = '\0';

	return buf;

error:
	list_for_every_safe(&element_list)
	{
		auto elem = container_of(l, struct path_element, node);
		dentry_put(elem->d);
		delete elem;
	}

	return nullptr;
}

}
