/*
 * Copyright (c) 2020 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <assert.h>
#include <errno.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <onyx/compiler.h>
#include <onyx/dentry.h>
#include <onyx/file.h>
#include <onyx/mtable.h>
#include <onyx/user.h>
#include <onyx/vfs.h>
#include <onyx/wait.h>

#include <onyx/expected.hpp>
#include <onyx/hashtable.hpp>
#include <onyx/list.hpp>
#include <onyx/mm/pool.hpp>
#include <onyx/string_view.hpp>

static memory_pool<dentry, 0> dentry_pool;
dentry *root_dentry = nullptr;

fnv_hash_t hash_dentry(dentry *&d)
{
    auto hash = fnv_hash(&d->d_parent, sizeof(dentry *));
    hash = fnv_hash_cont(d->d_name, d->d_name_length, hash);
    return hash;
}

fnv_hash_t hash_dentry_fields(dentry *parent, std::string_view name)
{
    auto hash = fnv_hash(&parent, sizeof(dentry *));
    hash = fnv_hash_cont(name.data(), name.length(), hash);
    return hash;
}

cul::hashtable2<dentry *, 1024, fnv_hash_t, hash_dentry> dentry_ht;
static rwslock dentry_ht_locks[1024];

[[gnu::always_inline]] static inline bool dentry_compare_name(dentry *dent,
                                                              std::string_view &to_cmp)
{
    std::string_view dent_name{dent->d_name, dent->d_name_length};

    return dent_name.compare(to_cmp) == 0;
}

dentry *dentry_open_from_cache_unlocked(dentry *dent, std::string_view name)
{
    auto namehash = fnv_hash(name.data(), name.length());
    auto hash = hash_dentry_fields(dent, name);
    auto index = dentry_ht.get_hashtable_index(hash);
    auto list = dentry_ht.get_hashtable(index);

    list_for_every (list)
    {
        dentry *d = container_of(l, dentry, d_cache_node);
        scoped_rwslock<rw_lock::read> g{d->d_lock};
        if (d->d_parent == dent && d->d_name_hash == namehash && dentry_compare_name(d, name))
        {
            dentry_get(d);

            return d;
        }
    }

    return nullptr;
}

dentry *dentry_open_from_cache(dentry *dent, std::string_view name)
{
    auto hash = hash_dentry_fields(dent, name);
    auto index = dentry_ht.get_hashtable_index(hash);
    scoped_rwslock<rw_lock::read> g{dentry_ht_locks[index]};

    return dentry_open_from_cache_unlocked(dent, name);
}

void dentry_remove_from_cache(dentry *dent, dentry *parent)
{
    auto hash = hash_dentry_fields(dent, std::string_view{dent->d_name, dent->d_name_length});
    auto index = dentry_ht.get_hashtable_index(hash);
    scoped_rwslock<rw_lock::write> g{dentry_ht_locks[index]};

    list_remove(&dent->d_cache_node);
}

void dentry_get(dentry *d)
{
    /* Must hold parent's d_lock */
    __atomic_add_fetch(&d->d_ref, 1, __ATOMIC_ACQUIRE);
}

void dentry_put(dentry *d)
{
    if (__atomic_sub_fetch(&d->d_ref, 1, __ATOMIC_RELEASE) == 0)
        dentry_destroy(d);
}

enum class fs_token_type : uint8_t
{
    REGULAR_TOKEN = 0,
    LAST_NAME_IN_PATH
};

struct last_name_handling
{
    virtual expected<dentry *, int> operator()(nameidata &data, std::string_view &name) = 0;
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

    unsigned int lookup_flags;

    nameidata(std::string_view view, dentry *root, dentry *rel, last_name_handling *h = nullptr)
        : view{view}, pos{}, root{root}, location{rel},
          token_type{fs_token_type::REGULAR_TOKEN}, nloops{0}, handler{h}, lookup_flags{0}
    {
    }

    nameidata for_symlink_resolution(std::string_view path) const
    {
        nameidata n{path, root, location};
        if (root)
            dentry_get(root);
        if (location)
            dentry_get(location);
        n.nloops = nloops;

        return n;
    }

    /* Used after resolving a symlink in path resolution */
    void track_symlink_count(nameidata &d)
    {
        nloops = d.nloops;
    }
};

void dentry_destroy(dentry *d)
{
    if (d->d_parent)
    {
        {
            scoped_rwslock<rw_lock::write> g{d->d_parent->d_lock};
            list_remove(&d->d_parent_dir_node);
        }

        dentry_remove_from_cache(d, d->d_parent);

        dentry_put(d->d_parent);
    }

    if (d->d_inode)
        inode_unref(d->d_inode);

    // printk("Dentry %s dead\n", d->d_name);

    if (d->d_name_length > INLINE_NAME_MAX)
    {
        free((void *) d->d_name);
    }

    d->~dentry();
    dentry_pool.free(d);
}

/**
 * @brief Fail a dentry lookup
 *
 * @param d Dentry
 */
static void dentry_fail_lookup(dentry *d)
{
    dentry_remove_from_cache(d, d->d_parent);

    {
        scoped_rwslock<rw_lock::write> g{d->d_parent->d_lock};
        list_remove(&d->d_parent_dir_node);
        dentry_put(d->d_parent);
        d->d_parent = nullptr;
        d->d_flags |= DENTRY_FLAG_FAILED;
        d->d_flags &= ~DENTRY_FLAG_PENDING;
    }

    wake_address((void *) &d->d_flags);
    dentry_put(d);
}

/**
 * @brief Complete a dentry lookup
 *
 * @param d Dentry
 */
static void dentry_complete_lookup(dentry *d)
{
    d->d_flags &= ~DENTRY_FLAG_PENDING;
    wake_address((void *) &d->d_flags);
}

void dentry_kill_unlocked(dentry *entry)
{
    assert(entry->d_ref == 1);

    if (entry->d_parent)
    {
        list_remove(&entry->d_parent_dir_node);
        dentry_put(entry->d_parent);
        entry->d_parent = nullptr;
    }

    dentry_remove_from_cache(entry, entry->d_parent);

    dentry_destroy(entry);
}

dentry *dentry_create(const char *name, inode *inode, dentry *parent)
{
    if (parent && !S_ISDIR(parent->d_inode->i_mode))
        return errno = ENOTDIR, nullptr;

    /* TODO: Move a bunch of this code to a constructor and placement-new it */
    dentry *new_dentry = dentry_pool.allocate();
    if (!new_dentry) [[unlikely]]
        return nullptr;

    new_dentry = new (new_dentry) dentry;

    new_dentry->d_ref = 1;
    new_dentry->d_name = new_dentry->d_inline_name;

    size_t name_length = strlen(name);

    if (name_length <= INLINE_NAME_MAX)
    {
        strlcpy(new_dentry->d_name, name, INLINE_NAME_MAX);
    }
    else
    {
        char *dname = (char *) memdup((void *) name, name_length + 1);
        if (!dname)
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
    if (inode)
        inode_ref(inode);
    new_dentry->d_parent = parent;

    if (parent) [[likely]]
    {
        list_add_tail(&new_dentry->d_parent_dir_node, &parent->d_children_head);
        dentry_get(parent);
    }

    INIT_LIST_HEAD(&new_dentry->d_children_head);

    new_dentry->d_mount_dentry = nullptr;
    new_dentry->d_flags = 0;

    return new_dentry;
}

bool dentry_is_dir(const dentry *d)
{
    return S_ISDIR(d->d_inode->i_mode);
}

dentry *dentry_wait_for_pending(dentry *dent)
{
    wait_for(
        &dent->d_flags,
        [](void *addr) -> bool {
            const uint16_t flags = *(uint16_t *) addr;
            return !(flags & DENTRY_FLAG_PENDING);
        },
        WAIT_FOR_FOREVER, 0);

    if (dent->d_flags & DENTRY_FLAG_FAILED)
    {
        dentry_put(dent);
        return nullptr;
    }

    assert(dent->d_inode != nullptr);

    return dent;
}

expected<dentry *, int> __dentry_create_pending_lookup(const char *name, inode *ino, dentry *parent,
                                                       bool check_existance)
{
    auto hash = hash_dentry_fields(parent, name);
    auto index = dentry_ht.get_hashtable_index(hash);
    scoped_rwslock<rw_lock::write> g{dentry_ht_locks[index]};
    auto list = dentry_ht.get_hashtable(index);

    auto dent = dentry_open_from_cache_unlocked(parent, std::string_view(name));

    if (dent)
    {
        g.unlock();
        dent = dentry_wait_for_pending(dent);

        if (dent && check_existance)
            return unexpected<int>{-EEXIST};
        else if (dent)
            return dent;
    }

    scoped_rwslock<rw_lock::write> g2{parent->d_lock};

    auto d = dentry_create(name, ino, parent);
    if (!d)
        return unexpected<int>{-ENOMEM};

    d->d_flags |= DENTRY_FLAG_PENDING;

    list_add_tail(&d->d_cache_node, list);
    return d;
}

expected<dentry *, int> dentry_create_pending_lookup(const char *name, inode *ino, dentry *parent,
                                                     bool check_existance = true)
{
    return __dentry_create_pending_lookup(name, ino, parent, check_existance);
}

dentry *__dentry_try_to_open(std::string_view name, dentry *dir)
{
    if (auto d = dentry_open_from_cache(dir, name); d)
    {
        if (d->d_flags & DENTRY_FLAG_PENDING)
        {
            d = dentry_wait_for_pending(d);

            return d;
        }
        else
            return d;
    }

    // For in memory filesystems like tmpfs where everything is in the dcache
    if (dir->d_inode->i_sb->s_flags & SB_FLAG_IN_MEMORY)
        return errno = ENOENT, nullptr;

    // printk("trying to open %.*s in %s\n", (int) name.length(), name.data(), dir->d_name);
    char _name[NAME_MAX + 1] = {};
    memcpy(_name, name.data(), name.length());
    auto ex = __dentry_create_pending_lookup(_name, nullptr, dir, false);

    if (ex.has_error())
        return errno = -ex.error(), nullptr;

    auto dent = ex.value();

    if (!(dent->d_flags & DENTRY_FLAG_PENDING))
    {
        // We got lucky and got someone else's resolution.
        // Easy.
        return dent;
    }

    auto pino = dir->d_inode;

    rw_lock_read(&pino->i_rwlock);

    inode *ino = dir->d_inode->i_fops->open(dir, _name);

    rw_unlock_read(&pino->i_rwlock);

    if (!ino)
    {
        // printk("failed\n");
        dentry_fail_lookup(dent);
        return nullptr;
    }

    dent->d_inode = ino;
    dentry_get(dent);
    if (dentry_is_dir(dent))
        ino->i_dentry = dent;

    dentry_complete_lookup(dent);

    return dent;
}

dentry *dentry_try_to_open_locked(std::string_view name, dentry *dir)
{
    scoped_rwslock<rw_lock::write> g{dir->d_lock};
    return __dentry_try_to_open(name, dir);
}

dentry *__dentry_parent(dentry *dir)
{
    auto ret = dir->d_parent;

    if (ret)
        dentry_get(ret);

    return ret;
}

dentry *dentry_parent(dentry *dir)
{
    scoped_rwslock<rw_lock::read> g{dir->d_lock};

    return __dentry_parent(dir);
}

dentry *dentry_lookup_internal(std::string_view v, dentry *dir, dentry_lookup_flags_t flags)
{
    bool resolve = !(flags & DENTRY_LOOKUP_DONT_TRY_TO_RESOLVE);

    if (!dentry_is_dir(dir))
    {
        return errno = ENOTDIR, nullptr;
    }

    if (!v.compare("."))
    {
        dentry_get(dir);
        return dir;
    }

    if (!v.compare(".."))
    {
        auto dent = dentry_parent(dir);
        if (!dent)
            dent = dir;
        dentry_get(dent);
        return dent;
    }

    dentry *dent = dentry_open_from_cache(dir, v);

    if (dent)
    {
        if (dent->d_flags & DENTRY_FLAG_PENDING)
        {
            dent = dentry_wait_for_pending(dent);

            if (dent)
                return dent;
            else
            {
                goto resolve;
            }
        }

        return dent;
    }

resolve:
    return resolve ? __dentry_try_to_open(v, dir) : nullptr;
}

dentry *dentry_mount(const char *mountpoint, struct inode *inode)
{
    if (!strcmp(mountpoint, "/")) [[unlikely]]
    {
        /* shortpath: We're creating the absolute root inode */
        auto d = (root_dentry = dentry_create(mountpoint, inode, nullptr));
        if (d)
            d->d_flags |= DENTRY_FLAG_MOUNT_ROOT;
        return d;
    }

    char *path = strdup(mountpoint);
    if (!path)
        return nullptr;

    auto fs_root = get_filesystem_root();
    dentry_get(fs_root->file->f_dentry);
    std::string_view name{mountpoint, strlen(mountpoint)};
    nameidata namedata{name, fs_root->file->f_dentry, nullptr};

    auto base_dentry = dentry_resolve(namedata);
    if (!base_dentry)
    {
        free((void *) path);
        return nullptr;
    }

    if (!dentry_is_dir(base_dentry))
    {
        free((void *) path);
        dentry_put(base_dentry);
        errno = ENOTDIR;
        return nullptr;
    }

    dentry *new_d = inode->i_dentry ?: dentry_create(basename(path), inode, base_dentry);

    if (inode->i_dentry)
    {
        /* TODO: I don't believe it's adjusting d_parent properly */
        dentry_put(inode->i_dentry->d_parent);
        dentry_get(base_dentry);
        inode->i_dentry->d_parent = base_dentry;
    }

    if (new_d)
    {
        base_dentry->d_lock.lock_write();
        if (base_dentry->d_flags & DENTRY_FLAG_MOUNTPOINT)
        {
            free((void *) path);
            base_dentry->d_lock.unlock_write();
            return errno = EBUSY, nullptr;
        }

        base_dentry->d_mount_dentry = new_d;
        base_dentry->d_flags |= DENTRY_FLAG_MOUNTPOINT;
        dentry_get(new_d);
        new_d->d_flags |= DENTRY_FLAG_MOUNT_ROOT;
        inode->i_dentry = new_d;

        base_dentry->d_lock.unlock_write();
    }

    free((void *) path);
    dentry_put(base_dentry);

    return new_d;
}

int mount_fs(struct inode *fsroot, const char *path)
{
    assert(fsroot != nullptr);

    printf("mount_fs: Mounting on %s\n", path);

    if (!strcmp(path, "/"))
    {
        file *f = (file *) zalloc(sizeof(*f));
        if (!f)
            return -ENOMEM;
        f->f_ino = fsroot;
        f->f_refcount = 1;
        f->f_dentry = dentry_mount("/", fsroot);
        assert(f->f_dentry != nullptr);

        auto fs_root = get_filesystem_root();
        if (fs_root->file)
        {
            fd_put(fs_root->file);
        }

        fs_root->file = f;
    }
    else
    {
        dentry *d;
        if (!(d = dentry_mount(path, fsroot)))
            return -errno;
        dentry_put(d);
    }

    return 0;
}

std::string_view get_token_from_path(nameidata &namedata)
{
    const auto &view = namedata.view;
    while (true)
    {
        namedata.pos = view.find_first_not_of('/', namedata.pos);
        if (namedata.pos == std::string_view::npos)
            break;

        auto path_elem_end = view.find('/', namedata.pos);
        // std::cout << "end at pos " << path_elem_end << "\n";
        // std::cout << "pos: " << pos << "\n";
        bool is_last_element = false;
        if (path_elem_end == std::string_view::npos) [[unlikely]]
        {
            is_last_element = true;
            path_elem_end = view.length();
        }
        else if (view.find_first_not_of('/', path_elem_end) == std::string_view::npos)
        {
            is_last_element = true;
        }

        namedata.token_type =
            is_last_element ? fs_token_type::LAST_NAME_IN_PATH : fs_token_type::REGULAR_TOKEN;

        // std::cout << "Elem size: " << path_elem_end - pos << "\n";
        std::string_view v = view.substr(namedata.pos, path_elem_end - namedata.pos);
        namedata.pos += v.length() + 1;
        // std::cout << "Path element: " << v << "\n";

        return v;
    }

    return {};
}

bool dentry_is_symlink(dentry *d)
{
    return d->d_inode->i_type == VFS_TYPE_SYMLINK;
}

bool dentry_is_mountpoint(dentry *dir)
{
    return dir->d_flags & DENTRY_FLAG_MOUNTPOINT;
}

expected<dentry *, int> dentry_follow_symlink(nameidata &data, dentry *symlink)
{
    file f;
    f.f_ino = symlink->d_inode;

    /* Oops - We hit the max symlink count */
    if (data.nloops++ == nameidata::max_loops)
    {
        return unexpected<int>{-ELOOP};
    }

    auto target_str = readlink_vfs(&f);
    if (!target_str)
    {
        return unexpected<int>{-errno};
    }

    /* Create a new nameidata for the new path, **with the current nloop**.
     * This makes it so we properly keep track of nloop.
     */

    auto new_nameidata = data.for_symlink_resolution({target_str, strlen(target_str)});

    auto symlink_target = dentry_resolve(new_nameidata);

    free((void *) target_str);

    if (!symlink_target)
    {
        return unexpected<int>{-errno};
    }

    /* We need to track the new structure's nloop as to keep a lookup-global count */
    data.track_symlink_count(new_nameidata);

    return symlink_target;
}

int __dentry_resolve_path(nameidata &data)
{
    std::string_view v;
    // printk("Resolving %s\n", data.view.data());
    bool dont_follow_last = data.lookup_flags & OPEN_FLAG_NOFOLLOW;

    while ((v = get_token_from_path(data)).data() != nullptr)
    {
        if (v.length() > NAME_MAX)
            return -ENAMETOOLONG;

        bool is_last_name = data.token_type == fs_token_type::LAST_NAME_IN_PATH;
        // printk("%.*s\n", (int) v.length(), v.data());
        if (is_last_name && data.handler)
        {
            // printk("^^ is last name\n");
            // printk("data.handler: %p\n", data.handler);
            auto ex = data.handler->operator()(data, v);
            if (ex.has_value())
            {
                dentry_put(data.location);
                data.location = ex.value();
                return 0;
            }

            return ex.error();
        }

        file f;
        f.f_ino = data.location->d_inode;
        if (!file_can_access(&f, FILE_ACCESS_EXECUTE))
        {
            return -EACCES;
        }

        dentry *new_found = nullptr;
        if (data.location == data.root && !v.compare("..")) [[unlikely]]
        {
            /* Stop from escaping the chroot */
            continue;
        }
        else
        {
            new_found = dentry_lookup_internal(v, data.location);
            if (!new_found)
            {
                return -errno;
            }
        }

        assert(new_found->d_inode != nullptr);

        if (dentry_is_symlink(new_found))
        {
            /* Posix states that paths that end in a trailing slash are required to be the same as
             * /. For example: open("/usr/bin/") == open("/usr/bin/."). Therefore, we have to
             * special case that.
             */

            const bool must_be_dir = data.lookup_flags & LOOKUP_FLAG_INTERNAL_TRAILING_SLASH;
            const bool should_follow_symlink = !dont_follow_last || must_be_dir;

            // printk("Following symlink for path elem %s\n", v.data());
            if (is_last_name && (data.lookup_flags & OPEN_FLAG_FAIL_IF_LINK))
            {
                dentry_put(new_found);
                return -ELOOP;
            }
            else if (is_last_name && !should_follow_symlink)
            {
                // printk("Cannot follow symlink. Trailing slash: %s\n", must_be_dir ? "yes" :
                // "no");
            }
            else [[likely]]
            {
                auto result = dentry_follow_symlink(data, new_found);
                dentry_put(new_found);

                if (!result)
                    return result.error();
                else
                    new_found = result.value();
            }
        }

        if (dentry_is_mountpoint(new_found))
        {
            auto dest = new_found->d_mount_dentry;
            dentry_put(new_found);
            new_found = dest;
            dentry_get(dest);
        }

        dentry_put(data.location);
        data.location = new_found;
    }

    return 0;
}

int dentry_resolve_path(nameidata &data)
{
    auto &pathname = data.view;

    auto pathname_length = pathname.length();
    if (pathname_length == 0)
    {
        if (data.lookup_flags & OPEN_FLAG_EMPTY_PATH)
        {
            assert(data.location != nullptr);
            dentry_get(data.location);
            return 0;
        }

        return -ENOENT;
    }

    // std::cout << "Total pathname: " << pathname << "\n";

    bool absolute = pathname[0] == '/';
    /*if(absolute)
        std::cout << "Pathname type: Absolute\n";
    else
        std::cout << "Pathname type: Relative\n";
    */

    if (pathname[pathname.length() - 1] == '/')
        data.lookup_flags |= LOOKUP_FLAG_INTERNAL_TRAILING_SLASH;
    bool must_be_dir =
        data.lookup_flags & (LOOKUP_FLAG_INTERNAL_TRAILING_SLASH | OPEN_FLAG_MUST_BE_DIR);

    if (absolute)
    {
        if (data.location)
            dentry_put(data.location);
        data.location = data.root;
        dentry_get(data.root);
    }

    data.view = std::string_view(&pathname[(int) absolute], pathname_length - (int) absolute);

    auto st = __dentry_resolve_path(data);

    if (absolute)
    {
        dentry_put(data.root);
    }

    if (st < 0)
    {
        dentry_put(data.location);
        return st;
    }

    if (!dentry_is_dir(data.location) && must_be_dir)
    {
        dentry_put(data.location);
        return -ENOTDIR;
    }

    return 0;
}

dentry *dentry_resolve(nameidata &data)
{
    int st = dentry_resolve_path(data);
    if (st < 0)
        return errno = -st, nullptr;
    return data.location;
}

file *open_vfs_with_flags(file *f, const char *name, unsigned int open_flags)
{
    bool unref_f = false;
    auto fs_root = get_filesystem_root();

    if (!f) [[unlikely]]
    {
        f = get_current_directory();
        unref_f = true;
        fd_get(f);
    }

    dentry_get(fs_root->file->f_dentry);
    dentry_get(f->f_dentry);

    nameidata namedata{std::string_view{name, strlen(name)}, fs_root->file->f_dentry, f->f_dentry};

    namedata.lookup_flags = open_flags;

    auto dent = dentry_resolve(namedata);

    if (unref_f) [[unlikely]]
        fd_put(f);

    if (!dent)
        return nullptr;

    auto new_file = inode_to_file(dent->d_inode);
    if (!new_file)
    {
        dentry_put(dent);
        return nullptr;
    }

    inode_ref(dent->d_inode);
    new_file->f_dentry = dent;

    return new_file;
}

struct file *open_vfs(struct file *dir, const char *path)
{
    return open_vfs_with_flags(dir, path, 0);
}

void dentry_init()
{
}

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
    create_handling(create_file_info info) : in{info}
    {
    }

    expected<dentry *, int> operator()(nameidata &data, std::string_view &name) override
    {
        // printk("Here.\n");
        auto dentry = data.location;
        auto inode = dentry->d_inode;

        if (!inode_can_access(inode, FILE_ACCESS_WRITE))
            return unexpected<int>{-EACCES};

        char _name[NAME_MAX + 1] = {};
        memcpy(_name, name.data(), name.length());

        if (in.type != create_file_type::mkdir &&
            data.lookup_flags & LOOKUP_FLAG_INTERNAL_TRAILING_SLASH)
            return unexpected<int>{-ENOTDIR};

        auto st = dentry_create_pending_lookup(_name, nullptr, dentry);

        if (st.has_error())
            return st;

        auto new_dentry = st.value();

        struct inode *new_inode = nullptr;

        rw_lock_write(&inode->i_rwlock);

        if (in.type == create_file_type::creat)
            new_inode = inode->i_fops->creat(_name, (int) in.mode | S_IFREG, dentry);
        else if (in.type == create_file_type::mkdir)
            new_inode = inode->i_fops->mkdir(_name, in.mode, dentry);
        else if (in.type == create_file_type::mknod)
            new_inode = inode->i_fops->mknod(_name, in.mode, in.dev, dentry);

        if (!new_inode)
        {
            rw_unlock_write(&inode->i_rwlock);
            dentry_fail_lookup(new_dentry);
            return unexpected<int>{-errno};
        }

        dentry_get(new_dentry);

        if (in.type == create_file_type::mkdir)
        {
            new_inode->i_dentry = new_dentry;
        }

        new_dentry->d_inode = new_inode;

        dentry_complete_lookup(new_dentry);
        rw_unlock_write(&inode->i_rwlock);

#if 0
		printk("cinode refs: %lu\n", new_inode->i_refc);
		printk("cdentry refs: %lu\n", new_dentry->d_ref);
		printk("pdentry refs: %lu\n", dentry->d_ref);
#endif
        return new_dentry;
    }
};

struct symlink_handling : public last_name_handling
{
    const char *dest;
    symlink_handling(const char *d) : dest{d}
    {
    }

    expected<dentry *, int> operator()(nameidata &data, std::string_view &name) override
    {
        auto dentry = data.location;
        auto inode = dentry->d_inode;

        if (!inode_can_access(inode, FILE_ACCESS_WRITE))
            return unexpected<int>{-EACCES};

        char _name[NAME_MAX + 1] = {};
        memcpy(_name, name.data(), name.length());

        auto ex = dentry_create_pending_lookup(_name, nullptr, dentry);
        if (ex.has_error())
            return ex;
        auto new_dentry = ex.value();
        // printk("Symlinking %s(%p)\n", _name, new_dentry);

        rw_lock_write(&inode->i_rwlock);

        auto new_ino = inode->i_fops->symlink(_name, dest, dentry);

        if (!new_ino)
        {
            rw_unlock_write(&inode->i_rwlock);
            dentry_fail_lookup(new_dentry);
            return unexpected<int>{-errno};
        }

        new_dentry->d_inode = new_ino;
        dentry_get(new_dentry);

        dentry_complete_lookup(new_dentry);

        rw_unlock_write(&inode->i_rwlock);

        return new_dentry;
    }
};

dentry *generic_last_name_helper(dentry *base, const char *path, last_name_handling &h,
                                 unsigned int lookup_flags = 0)
{
    auto fs_root = get_filesystem_root();

    dentry_get(fs_root->file->f_dentry);
    dentry_get(base);

    nameidata namedata{std::string_view{path, strlen(path)}, fs_root->file->f_dentry, base, &h};
    namedata.lookup_flags = lookup_flags;

    return dentry_resolve(namedata);
}

/* Helper to open specific dentries */
dentry *dentry_do_open(dentry *base, const char *path, unsigned int lookup_flags = 0)
{
    auto fs_root = get_filesystem_root();

    dentry_get(fs_root->file->f_dentry);
    dentry_get(base);

    nameidata namedata{std::string_view{path, strlen(path)}, fs_root->file->f_dentry, base};
    namedata.lookup_flags = lookup_flags;

    return dentry_resolve(namedata);
}

file *file_creation_helper(dentry *base, const char *path, last_name_handling &h)
{
    // assert((void *) &h.operator() != nullptr);
    auto dent = generic_last_name_helper(base, path, h);
    if (!dent)
        return nullptr;

    auto new_file = inode_to_file(dent->d_inode);
    if (!new_file)
    {
        dentry_put(dent);
        return nullptr;
    }

    inode_ref(dent->d_inode);

    new_file->f_dentry = dent;

    return new_file;
}

file *creat_vfs(dentry *base, const char *path, int mode)
{
    // Mask out the possible file type bits and set IFREG for a regular creat
    mode &= ~S_IFMT;
    mode |= S_IFREG;

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

    if (fs_root == dentry)
        return strdup("/");

    dentry_get(fs_root);

    auto d = dentry;
    struct list_head element_list;
    INIT_LIST_HEAD(&element_list);

    /* Get another ref here to have prettier code */
    dentry_get(d);

    /* TODO: Is this logic safe from race conditions? */
    while (d != fs_root && d != nullptr)
    {
        path_element *p = new path_element;
        if (!p)
            goto error;
        p->d = d;
        /* Add 1 to the len because of the separator */
        buf_len += d->d_name_length + 1;
        list_add(&p->node, &element_list);

        if (d->d_flags & DENTRY_FLAG_MOUNT_ROOT)
        {
            d = dentry_parent(d);
            if (d)
                d = dentry_parent(d);
        }
        else
            d = dentry_parent(d);
    }

    /* Remove one from the end to avoid trailing slashes */
    buf_len--;

    buf = (char *) malloc(buf_len);
    if (!buf)
        goto error;
    buf[0] = '/';
    s = &buf[1];

    list_for_every_safe (&element_list)
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
    list_for_every_safe (&element_list)
    {
        auto elem = container_of(l, struct path_element, node);
        dentry_put(elem->d);
        delete elem;
    }

    return nullptr;
}

struct link_handling : public last_name_handling
{
    file *dest;
    link_handling(struct file *d) : dest{d}
    {
    }

    expected<dentry *, int> operator()(nameidata &data, std::string_view &name) override
    {
        auto dentry = data.location;
        auto inode = dentry->d_inode;
        auto dest_ino = dest->f_ino;

        if (!inode_can_access(inode, FILE_ACCESS_WRITE))
            return unexpected<int>{-EACCES};

        if (inode->i_dev != dest_ino->i_dev)
            return unexpected<int>{-EXDEV};

        char _name[NAME_MAX + 1] = {};
        memcpy(_name, name.data(), name.length());

        auto ex = dentry_create_pending_lookup(_name, dest_ino, dentry);
        if (ex.has_error())
            return ex;

        auto new_dentry = ex.value();

        rw_lock_write(&inode->i_rwlock);

        auto st = inode->i_fops->link(dest, _name, dentry);

        if (st < 0)
        {
            rw_unlock_write(&inode->i_rwlock);
            dentry_fail_lookup(new_dentry);
            return unexpected<int>{st};
        }

        inode_inc_nlink(dest_ino);

        dentry_get(new_dentry);

        dentry_complete_lookup(new_dentry);

        rw_unlock_write(&inode->i_rwlock);

        return new_dentry;
    }
};

int link_vfs(struct file *target, dentry *rel_base, const char *newpath)
{
    link_handling h{target};
    auto_dentry f = generic_last_name_helper(rel_base, newpath, h);
    if (!f)
        return -errno;

    return 0;
}

#define VALID_LINKAT_FLAGS (AT_SYMLINK_FOLLOW | AT_EMPTY_PATH)

int do_sys_link(int olddirfd, const char *uoldpath, int newdirfd, const char *unewpath, int flags)
{
    if (flags & ~VALID_LINKAT_FLAGS)
        return -EINVAL;

    unsigned int lookup_flags = OPEN_FLAG_NOFOLLOW;

    if (flags & AT_EMPTY_PATH)
        lookup_flags |= OPEN_FLAG_EMPTY_PATH;

    user_string oldpath, newpath;

    if (auto res = oldpath.from_user(uoldpath); !res.has_value())
        return res.error();

    if (auto res = newpath.from_user(unewpath); !res.has_value())
        return res.error();

    auto_file olddir, newdir;

    if (auto st = olddir.from_dirfd(olddirfd); st != 0)
        return st;

    if (auto st = newdir.from_dirfd(newdirfd); st != 0)
        return st;

    if (flags & AT_SYMLINK_FOLLOW)
        lookup_flags &= ~OPEN_FLAG_NOFOLLOW;

    auto_file src_file = open_vfs_with_flags(olddir.get_file(), oldpath.data(), lookup_flags);

    if (!src_file)
        return -errno;

    if (src_file.is_dir())
        return -EPERM;

    return link_vfs(src_file.get_file(), newdir.get_file()->f_dentry, newpath.data());
}

int sys_link(const char *oldpath, const char *newpath)
{
    return do_sys_link(AT_FDCWD, oldpath, AT_FDCWD, newpath, 0);
}

int sys_linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags)
{
    return do_sys_link(olddirfd, oldpath, newdirfd, newpath, flags);
}

void dentry_do_unlink(dentry *entry)
{
    /* Perform the actual unlink, by write-locking, nulling d_parent */
    entry->d_lock.lock_write();

    auto parent = entry->d_parent;

    entry->d_parent = nullptr;

    inode_dec_nlink(entry->d_inode);
    // printk("unlink %s nlink: %lu nref %lu\n", entry->d_name, entry->d_inode->i_nlink,
    // entry->d_ref);

    if (dentry_is_dir(entry))
    {
        inode_dec_nlink(parent->d_inode);
        inode_dec_nlink(entry->d_inode);
    }

    dentry_remove_from_cache(entry, parent);

    entry->d_lock.unlock_write();

    // We can do this because we're holding the parent dir's lock
    list_remove(&entry->d_parent_dir_node);

    /* Lastly, release the references */
    dentry_put(entry);
}

bool dentry_involved_with_mount(dentry *d)
{
    return d->d_flags & (DENTRY_FLAG_MOUNTPOINT | DENTRY_FLAG_MOUNT_ROOT);
}

struct unlink_handling : public last_name_handling
{
    int flags;
    unlink_handling(int _flags) : flags{_flags}
    {
    }

    expected<dentry *, int> operator()(nameidata &data, std::string_view &name) override
    {
        /* Don't let the user unlink these two special entries */
        if (!name.compare(".") || !name.compare(".."))
            return unexpected<int>{-EINVAL};

        auto dentry = data.location;
        auto inode = dentry->d_inode;

        if (!inode_can_access(inode, FILE_ACCESS_WRITE))
            return unexpected<int>{-EACCES};

        char _name[NAME_MAX + 1] = {};
        memcpy(_name, name.data(), name.length());

        auto child = dentry_lookup_internal(name, dentry);
        if (!child)
            return unexpected<int>{-errno};

        /* Can't do that... Note that dentry always exists if it's a mountpoint */
        if (child && dentry_involved_with_mount(child))
        {
            dentry_put(child);
            return unexpected<int>{-EBUSY};
        }

        rw_lock_write(&inode->i_rwlock);
        /* Do the actual fs unlink */
        auto st = inode->i_fops->unlink(_name, flags, dentry);

        if (st < 0)
        {
            rw_unlock_write(&inode->i_rwlock);
            dentry_put(child);
            return unexpected<int>{st};
        }

        /* The fs unlink succeeded! Lets change the dcache now that we can't fail! */
        if (child)
        {
            scoped_rwslock<rw_lock::write> g{dentry->d_lock};

            dentry_do_unlink(child);

            /* Release the reference that we got from dentry_lookup_internal */
            dentry_put(child);
        }

        rw_unlock_write(&inode->i_rwlock);

        /* Return the parent directory as a cookie so the calling code doesn't crash and die */
        return dentry;
    }
};

int unlink_vfs(const char *path, int flags, struct file *node)
{
    unlink_handling h{flags};
    auto dent = generic_last_name_helper(node->f_dentry, path, h, OPEN_FLAG_NOFOLLOW);
    if (!dent)
        return -errno;
    dentry_put(dent);
    return 0;
}

#define VALID_UNLINKAT_FLAGS AT_REMOVEDIR

int do_sys_unlink(int dirfd, const char *upathname, int flags)
{
    auto_file dir;
    user_string pathname;

    if (flags & ~VALID_UNLINKAT_FLAGS)
        return -EINVAL;

    if (auto st = dir.from_dirfd(dirfd); st != 0)
        return st;

    if (auto res = pathname.from_user(upathname); !res.has_value())
        return res.error();
    return unlink_vfs(pathname.data(), flags, dir.get_file());
}

int sys_unlink(const char *pathname)
{
    return do_sys_unlink(AT_FDCWD, pathname, 0);
}

int sys_unlinkat(int dirfd, const char *pathname, int flags)
{
    return do_sys_unlink(dirfd, pathname, flags);
}

int sys_rmdir(const char *pathname)
{
    /* Thankfully we can implement rmdir with unlinkat semantics
     * Thanks POSIX for this really nice and thoughtful API! */
    return do_sys_unlink(AT_FDCWD, pathname, AT_REMOVEDIR);
}

int sys_symlinkat(const char *utarget, int newdirfd, const char *ulinkpath)
{
    auto_file dir;
    user_string target, linkpath;

    if (auto res = target.from_user(utarget); !res.has_value())
        return res.error();
    if (auto res = linkpath.from_user(ulinkpath); !res.has_value())
        return res.error();
    if (auto st = dir.from_dirfd(newdirfd); st < 0)
        return st;

    auto f = symlink_vfs(linkpath.data(), target.data(), dir.get_file()->f_dentry);
    if (!f)
        return -errno;

    fd_put(f);
    return 0;
}

int sys_symlink(const char *target, const char *linkpath)
{
    return sys_symlinkat(target, AT_FDCWD, linkpath);
}

bool dentry_does_not_have_parent(dentry *dir, dentry *to_not_have)
{
    auto_dentry fs_root = get_filesystem_root()->file->f_dentry;

    auto_dentry d = dir;

    /* Get another ref here to have prettier code */
    dentry_get(d.get_dentry());

    /* TODO: Is this logic safe from race conditions? */
    while (d.get_dentry() != fs_root.get_dentry() && d.get_dentry() != nullptr)
    {
        if (d.get_dentry() == to_not_have)
        {
            return false;
        }

        d = __dentry_parent(d.get_dentry());
    }

    return true;
}

void dentry_move(dentry *target, dentry *new_parent)
{
    list_remove(&target->d_parent_dir_node);

    list_add_tail(&target->d_parent_dir_node, &new_parent->d_children_head);

    auto old = target->d_parent;
    target->d_parent = new_parent;

    if (dentry_is_dir(target))
        inode_dec_nlink(old->d_inode);

    dentry_get(old);
}

void dentry_rename(dentry *dent, const char *name)
{
    size_t name_length = strlen(name);

    if (name_length <= INLINE_NAME_MAX)
    {
        strlcpy(dent->d_name, name, INLINE_NAME_MAX);

        /* It's in this exact order so we don't accidentally touch free'd memory or
         * an invalid d_name that resulted from a non-filled inline d_name.
         */
        if (dent->d_name != dent->d_inline_name)
        {
            auto old = dent->d_name;
            dent->d_name = dent->d_inline_name;
            free(old);
        }
    }
    else
    {
        char *dname = (char *) memdup(name, name_length + 1);
        /* TODO: Ugh, how do I handle this? */
        assert(dname != nullptr);

        auto old = dent->d_name;

        dent->d_name = dname;

        if (old != dent->d_inline_name)
        {
            free(old);
        }
    }

    dent->d_name_length = name_length;
    dent->d_name_hash = fnv_hash(dent->d_name, dent->d_name_length);
}

struct rename_handling : public last_name_handling
{
    dentry *old;
    rename_handling(dentry *_old) : old{_old}
    {
    }

    expected<dentry *, int> operator()(nameidata &data, std::string_view &name) override
    {
        // printk("Here\n");
        /* Don't let the user rename these two special entries */
        if (!name.compare(".") || !name.compare(".."))
            return unexpected<int>{-EINVAL};

        auto dir = data.location;
        // printk("location %s\n", dir->d_name);
        // printk("last name %.*s\n", (int) name.length(), name.data());
        auto inode = dir->d_inode;

        /* We've got multiple cases to handle here:
         * 1) name exists: We atomically replace them.
         * 2) oldpath and newpath are the same inode: We return success.
         * 3) Name doesn't exist: just link() the dentry.
         */

        dentry *__dir1, *__dir2;

        /* Establish a locking order to avoid deadlocks */

        if ((unsigned long) dir < (unsigned long) old)
        {
            __dir1 = dir;
            __dir2 = old;
        }
        else
        {
            __dir1 = old;
            __dir2 = dir;
        }

        // printk("dir1 %s dir2 %s\n", __dir1->d_name, __dir2->d_name);

        if (dir->d_inode->i_dev != old->d_inode->i_dev)
            return unexpected<int>{-EXDEV};

        if (old->d_inode == dir->d_inode)
            return unexpected<int>{-EINVAL};

        auto sb = inode->i_sb;

        if (!inode_can_access(inode, FILE_ACCESS_WRITE))
            return unexpected<int>{-EACCES};

        scoped_mutex rename_lock_guard{sb->s_rename_lock};

        char _name[NAME_MAX + 1] = {};
        memcpy(_name, name.data(), name.length());

        // printk("lookup0\n");
        dentry *dest = dentry_lookup_internal(name, dir);
        // printk("lookup1\n");

        /* Can't do that... Note that dentry always exists if it's a mountpoint */
        if (dest && dentry_involved_with_mount(dest))
        {
            dentry_put(dest);
            return unexpected<int>{-EBUSY};
        }

        scoped_rwlock<rw_lock::write> g{__dir1->d_inode->i_rwlock};
        scoped_rwlock<rw_lock::write> g2{__dir2->d_inode->i_rwlock};

        if (dest)
        {
            /* Case 2: dest inode = source inode */
            if (dest->d_inode == old->d_inode)
            {
                return dest;
            }

            /* Not sure if this is 100% correct */
            if (dentry_is_dir(old) ^ dentry_is_dir(dest))
            {
                dentry_put(dest);
                return unexpected<int>{-EISDIR};
            }
        }

        auto old_parent = __dentry_parent(old);

        if (!old_parent)
        {
            if (dest)
                dentry_put(dest);

            return unexpected<int>{-ENOENT};
        }

        /* It's invalid to try to make a directory be a subdirectory of itself */
        if (!dentry_does_not_have_parent(dir, old))
        {
            if (dest)
                dentry_put(dest);
            return unexpected<int>{-EINVAL};
        }

        /* Do the actual fs unlink(if dest exists) + link + unlink */
        /* The overall strategy here is to do everything that may fail first - so, for example,
         * everything that involves I/O or memory allocation. After that, we're left with the
         * bookkeeping, which can't fail.
         */
        int st = 0;

        // printk("Here3\n");

        if (dest)
        {
            /* Unlink the name on disk first */
            /* Note that i_fops->unlink() checks if the directory is empty, if it is one. */
            st = inode->i_fops->unlink(_name, AT_REMOVEDIR, dir);
        }

        // printk("(may have) unlinked\n");

        if (st < 0)
        {
            if (dest)
                dentry_put(dest);
            return unexpected<int>{st};
        }

        struct file f;
        f.f_ino = old->d_inode;
        f.f_dentry = old;

        /* Now link the name on disk */
        st = inode->i_fops->link(&f, _name, dir);

        // printk("linked\n");

        // printk("unlinking\n");

        /* rename allows us to move a non-empty dir. Because of that we
         * pass a special flag (UNLINK_VFS_DONT_TEST_EMPTY) to the fs, that allows us to do that.
         */
        st = old_parent->d_inode->i_fops->unlink(
            old->d_name, AT_REMOVEDIR | UNLINK_VFS_DONT_TEST_EMPTY, old_parent);

        // printk("done\n");

        /* TODO: What should we do if we fail in the middle? */
        if (st < 0)
        {
            if (dest)
                dentry_put(dest);
            return unexpected<int>{st};
        }

        /* The fs unlink succeeded! Lets change the dcache now that we can't fail! */
        if (dest)
            dentry_do_unlink(dest);

        // printk("doing move\n");
        /* No need to move if we're already under the same parent. */
        if (old_parent != dir)
            dentry_move(old, dir);

        // printk("done\n");

        dentry_rename(old, _name);

        /* Return the parent directory as a cookie so the calling code doesn't crash and die */
        return dir;
    }
};

int sys_renameat(int olddirfd, const char *uoldpath, int newdirfd, const char *unewpath)
{
    auto_file olddir, newdir;
    user_string oldpath, newpath;

    if (auto res = oldpath.from_user(uoldpath); res.has_error())
        return res.error();
    if (auto res = newpath.from_user(unewpath); res.has_error())
        return res.error();

    if (int st = olddir.from_dirfd(olddirfd); st < 0)
        return st;

    if (int st = newdir.from_dirfd(newdirfd); st < 0)
        return st;

    /* rename operates on the old and new symlinks and not their destination */
    auto_dentry old =
        dentry_do_open(olddir.get_file()->f_dentry, oldpath.data(), OPEN_FLAG_NOFOLLOW);
    if (!old)
        return -errno;

    /* Although this doesn't need to be an error, we're considering it as one in the meanwhile */
    if (dentry_involved_with_mount(old.get_dentry()))
        return -EBUSY;

    if (!inode_can_access(old.get_dentry()->d_inode, FILE_ACCESS_WRITE))
        return -EACCES;

    rename_handling h{old.get_dentry()};

    auto_dentry dent = generic_last_name_helper(newdir.get_file()->f_dentry, newpath.data(), h);
    if (!dent)
        return -errno;
    return 0;
}

int sys_rename(const char *oldpath, const char *newpath)
{
    return sys_renameat(AT_FDCWD, oldpath, AT_FDCWD, newpath);
}

bool dentry_is_empty(dentry *dir)
{
    scoped_rwslock<rw_lock::write> g{dir->d_lock};
    return list_is_empty(&dir->d_children_head);
}

cul::atomic_size_t killed_dentries = 0;

/**
 * @brief Trim the dentry caches
 *
 */
void dentry_trim_caches()
{
    auto currdent = root_dentry;
    dentry_get(currdent);
    linked_list<dentry *> dentry_queue;

    // For every dentry, try to evict unused children
    while (currdent)
    {

        // If ref > 1, we *may* have children
        if (currdent->d_ref > 1)
        {
            scoped_rwslock<rw_lock::write> g{currdent->d_lock};

            list_for_every_safe (&currdent->d_children_head)
            {
                dentry *d = container_of(l, dentry, d_parent_dir_node);

                if (d->d_ref == 1)
                {
                    // If we're destroying this dentry, take a peek at the parent and
                    // check if they have a ref of 2 (refe'd by themselves for existing, and us)
                    // If so, add their parent to the queue so we can revisit this later.
                    if (d->d_parent && d->d_parent->d_ref == 2)
                    {
                        auto parent = dentry_parent(d->d_parent);
                        dentry_queue.add(parent);
                    }

                    killed_dentries++;
                    // Ready for destruction, remove and destroy
                    dentry_kill_unlocked(d);
                }
                else
                {
                    // Still has refs. If directory, try and clean it up next
                    if (dentry_is_dir(d))
                    {
                        // We need to ref dentries, so we don't lose them magically
                        dentry_get(d);
                        dentry_queue.add(d);
                    }
                }
            }
        }

        dentry_put(currdent);

        currdent = dentry_queue.is_empty() ? nullptr : dentry_queue.pop_head();
    }

    dentry_pool.purge();
}
