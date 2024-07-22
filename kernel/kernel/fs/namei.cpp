/*
 * Copyright (c) 2020 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <onyx/cred.h>
#include <onyx/dentry.h>
#include <onyx/file.h>
#include <onyx/namei.h>
#include <onyx/process.h>
#include <onyx/user.h>

#include <uapi/fcntl.h>

#include <onyx/memory.hpp>

// XXX(heat): lookup root seems to leak

std::string_view get_token_from_path(path &path, bool no_consume_if_last)
{
    const auto &view = path.view;
    while (true)
    {
        path.pos = view.find_first_not_of('/', path.pos);
        if (path.pos == std::string_view::npos)
            break;

        auto path_elem_end = view.find('/', path.pos);
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

        path.token_type =
            is_last_element ? fs_token_type::LAST_NAME_IN_PATH : fs_token_type::REGULAR_TOKEN;

        // std::cout << "Elem size: " << path_elem_end - pos << "\n";
        std::string_view v = view.substr(path.pos, path_elem_end - path.pos);
        if (!(is_last_element && no_consume_if_last))
            path.pos += v.length() + 1;
        // std::cout << "Path element: " << v << "\n";

        return v;
    }

    return {};
}

/* XXX refactor this into we not needing this. name is purposefully clunky
 * Why is this here?
 * because inside namei_walk_component, we don't maintain nameidata::parent, and when we call into
 * this function we end up having data.location = parent. Other callers had namei_walk_component
 * place symlink into data.location, and parent into data.parent.
 */
#define DENTRY_FOLLOW_SYMLINK_NOT_NAMEI_WALK_COMPONENT (1U << 0)
static int dentry_follow_symlink(nameidata &data, dentry *symlink, unsigned int flags = 0)
{
    file f;
    f.f_ino = symlink->d_inode;

    /* Oops - We hit the max symlink count */
    if (++data.nloops == nameidata::max_loops)
    {
        return -ELOOP;
    }

    auto target_str = readlink_vfs(&f);
    if (!target_str)
    {
        return -errno;
    }

    /* Empty symlinks = -ENOENT. See nameitests for more info. */
    if (target_str[0] == '\0')
        return -ENOENT;

    // XXX make it expand
    CHECK(++data.pdepth < SYMLOOP_MAX);

    auto &path = data.paths[data.pdepth];
    if (path.ownbuf)
        free(path.ownbuf);
    path.ownbuf = target_str;
    path.view = std::string_view{target_str};
    path.pos = 0;
    path.token_type = fs_token_type::REGULAR_TOKEN;

    if (path.view.length() >= PATH_MAX)
        return -ENAMETOOLONG;

    if (target_str[0] == '/')
    {
        /* Switch location to root */
        dentry_put(data.cur);
        data.cur = data.root;
        dentry_get(data.cur);
    }
    else if (flags & DENTRY_FOLLOW_SYMLINK_NOT_NAMEI_WALK_COMPONENT)
    {
        dentry_put(data.cur);
        data.cur = data.parent;
        data.parent = nullptr;
    }

    return 0;
}

#define NAMEI_UNLOCKED       (1U << 0)
#define NAMEI_NO_FOLLOW_SYM  (1U << 1)
#define NAMEI_ALLOW_NEGATIVE (1U << 2)

static int namei_walk_component(std::string_view v, nameidata &data, unsigned int flags = 0)
{
    const bool is_last_name =
        data.paths[data.pdepth].token_type == fs_token_type::LAST_NAME_IN_PATH;
    const bool dont_follow_last = data.lookup_flags & LOOKUP_NOFOLLOW;
    const bool unlocked_lookup = flags & NAMEI_UNLOCKED;

    auto_dentry dwrapper;
    dentry *new_found;

    file f;
    f.f_ino = data.cur->d_inode;

    if (!dentry_is_dir(data.cur))
        return -ENOTDIR;

    if (!file_can_access(&f, FILE_ACCESS_EXECUTE))
        return -EACCES;

    if (data.cur == data.root && !v.compare("..")) [[unlikely]]
    {
        /* Stop from escaping the chroot */
        return 0;
    }
    else
    {
        dwrapper =
            dentry_lookup_internal(v, data.cur, unlocked_lookup ? DENTRY_LOOKUP_UNLOCKED : 0);
        if (!dwrapper)
        {
            DCHECK(errno != 0);
            return -errno;
        }

#if 0
        printk("Lookup %s found %p%s\n", v.data(), new_found,
               d_is_negative(new_found) ? " (negative)" : "");
#endif
    }

    new_found = dwrapper.get_dentry();

    if (d_is_negative(new_found))
    {
        /* Check if the caller tolerates negative dentries as the lookup result. This only applies
         * for the last name. For !last_name, negative is always ENOENT */
        if (!is_last_name || !(flags & NAMEI_ALLOW_NEGATIVE))
            return -ENOENT;
    }
    else if (dentry_is_symlink(new_found))
    {
        if (flags & NAMEI_NO_FOLLOW_SYM)
        {
            /* Save parent and location for the caller */
            data.setcur(dwrapper.release());
            return 0;
        }
        /* POSIX states that paths that end in a trailing slash are required to be the same as
         * /. For example: open("/usr/bin/") == open("/usr/bin/."). Therefore, we have to
         * special case that.
         */

        const bool must_be_dir = data.paths[data.pdepth].trailing_slash();
        const bool should_follow_symlink = !dont_follow_last || must_be_dir;

        // printk("Following symlink for path elem %s\n", v.data());
        if (is_last_name && (data.lookup_flags & LOOKUP_FAIL_IF_LINK))
            return -ELOOP;
        else if (is_last_name && !should_follow_symlink)
        {
            // printk("Cannot follow symlink. Trailing slash: %s\n", must_be_dir ? "yes" :
            // "no");
        }
        else [[likely]]
        {
            return dentry_follow_symlink(data, new_found);
        }
    }
    else if (dentry_is_mountpoint(new_found))
    {
        auto dest = new_found->d_mount_dentry;
        dentry_get(dest);
        dwrapper = dest;
        new_found = dwrapper.get_dentry();
    }

    data.setcur(dwrapper.release());

    return 0;
}

/**
 * @brief Do path resolution
 *
 * @param data Relevant data for the namei operation (see nameidata docs)
 * @return 0 on success, negative error codes
 */
static int namei_resolve_path(nameidata &data)
{
    std::string_view v;
    // printk("Resolving %s\n", data.paths[0].view.data());

    /* If we get a null path here, assume the caller did the proper sanitation, so this could be
     * something akin to: open("/"), where the first slash was already consumed and now we're left
     * with an empty path; so return success.
     */
    if (data.paths[data.pdepth].view.length() == 0)
        return 0;

    for (;;)
    {
#define NAMEI_DEBUG 0
#if NAMEI_DEBUG
        printk("pdepth %d %s %s\n", data.pdepth, data.paths[data.pdepth].view.data(),
               data.paths[data.pdepth].token_type == fs_token_type::LAST_NAME_IN_PATH ? "last"
                                                                                      : "regular");
#endif
        auto &path = data.paths[data.pdepth];
        if (path.token_type == fs_token_type::LAST_NAME_IN_PATH)
        {
            if (path.trailing_slash())
            {
                // Check if we indeed opened a directory here
                if (!dentry_is_dir(data.cur))
                    return -ENOTDIR;
            }

            if (data.pdepth == 0)
                return 0;
            data.pdepth--;
            continue;
        }

        /* Get the next token from the path.
         * Note that it does not consume *if* this is the last token and the caller asked for us not
         * to do so.
         */
        v = get_token_from_path(path, data.lookup_flags & LOOKUP_DONT_DO_LAST_NAME);
        if (v.length() > NAME_MAX)
            return -ENAMETOOLONG;

        if (data.lookup_flags & LOOKUP_DONT_DO_LAST_NAME &&
            path.token_type == fs_token_type::LAST_NAME_IN_PATH)
        {
            /* Pretend we didn't see this. */
            path.token_type = fs_token_type::REGULAR_TOKEN;
            data.lookup_flags |= LOOKUP_INTERNAL_SAW_LAST_NAME;
            return 0;
        }

        bool is_last_name = data.pdepth == 0 &&
                            data.paths[data.pdepth].token_type == fs_token_type::LAST_NAME_IN_PATH;

        if (is_last_name && data.handler)
        {
            // printk("^^ is last name\n");
            // printk("data.handler: %p\n", data.handler);
            auto ex = data.handler->operator()(data, v);
            if (ex.has_value())
            {
                dentry_put(data.cur);
                data.cur = ex.value();
                return 0;
            }

            return ex.error();
        }

        int st = namei_walk_component(v, data);
        if (st < 0)
            return st;
    }

    return 0;
}

int lookup_start(nameidata &data)
{
    auto &path = data.paths[data.pdepth];
    bool absolute = path.view[0] == '/';

    if (absolute)
    {
        if (data.cur)
            dentry_put(data.cur);
        data.cur = data.root;
        dentry_get(data.root);
    }

    path.view = std::string_view(&path.view[(int) absolute], path.view.length() - (int) absolute);

    return 0;
}

int namei_lookup(nameidata &data)
{
    auto &pathname = data.paths[data.pdepth].view;

    auto pathname_length = pathname.length();

    if (pathname_length >= PATH_MAX)
        return -ENAMETOOLONG;
    if (pathname_length == 0)
    {
        if (data.lookup_flags & LOOKUP_EMPTY_PATH)
        {
            assert(data.cur != nullptr);
            dentry_get(data.cur);
            return 0;
        }

        return -ENOENT;
    }

    lookup_start(data);

    bool must_be_dir = data.lookup_flags & (LOOKUP_INTERNAL_TRAILING_SLASH | LOOKUP_MUST_BE_DIR);

    auto st = namei_resolve_path(data);

    if (st < 0)
    {
        dentry_put(data.cur);
        return st;
    }

    if (!dentry_is_dir(data.cur) && must_be_dir)
    {
        dentry_put(data.cur);
        return -ENOTDIR;
    }

    return 0;
}

nameidata::~nameidata()
{
    // Clean up
    // Note that .cur is always not unrefed, as the result of the lookup
    if (parent)
        dentry_put(parent);
}

dentry *dentry_resolve(nameidata &data)
{
    int st = namei_lookup(data);
    if (st < 0)
        return errno = -st, nullptr;
    return data.cur;
}

file *open_vfs_with_flags(file *f, const char *name, unsigned int lookup_flags
#if 0
                            ,unsigned int open_flags, mode_t mode
#endif
)
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

    namedata.lookup_flags = lookup_flags;

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

static int do_creat(dentry *dir, struct inode *inode, struct dentry *dentry, mode_t mode,
                    nameidata &data)
{
    if (!inode_can_access(inode, FILE_ACCESS_WRITE))
        return -EACCES;

    if (data.lookup_flags & LOOKUP_INTERNAL_TRAILING_SLASH)
        return -ENOTDIR;

    DCHECK(d_is_negative(dentry));

    struct inode *new_inode = inode->i_fops->creat(dentry, (int) mode | S_IFREG, dir);

    if (!new_inode)
        return -errno;

    d_positiveize(dentry, new_inode);
    return 0;
}

static int do_last_open(nameidata &data, int open_flags, mode_t mode)
{
    dentry *cur = data.cur;
    inode *curino = cur->d_inode;
    bool lockwrite = open_flags & O_CREAT;
    int st = 0;
    auto &path = data.paths[data.pdepth];
    unsigned int lookup_flags = NAMEI_UNLOCKED | NAMEI_NO_FOLLOW_SYM;

    if (open_flags & O_CREAT)
    {
        /* We want to get negative dentries too for O_CREAT */
        lookup_flags |= NAMEI_ALLOW_NEGATIVE;
    }

    DCHECK(data.lookup_flags & LOOKUP_INTERNAL_SAW_LAST_NAME);

    data.lookup_flags &= ~LOOKUP_INTERNAL_SAW_LAST_NAME;

    if (lockwrite)
        inode_lock(curino);
    else
        inode_lock_shared(curino);

    auto last = get_token_from_path(path, false);
    DCHECK(last.data() != nullptr);

    if (open_flags & O_CREAT && path.trailing_slash())
    {
        st = -ENOTDIR;
        goto out;
    }

    st = namei_walk_component(last, data, lookup_flags);

    if (st < 0 || (open_flags & O_CREAT && d_is_negative(data.cur)))
    {
        /* Failed to walk, try to creat if we can */
        if (open_flags & O_CREAT)
            st = do_creat(cur, curino, data.cur, mode, data);
    }
    else
    {
        /* Ok, we found the component, great. */
        /* First, handle symlinks */

        if (dentry_is_symlink(data.cur))
        {
            if ((open_flags & (O_EXCL | O_CREAT)) == (O_EXCL | O_CREAT))
            {
                /* If O_EXCL and O_CREAT are set, and path names a symbolic link, open() shall fail
                 * and set errno to [EEXIST], regardless of the contents of the symbolic link. */
                st = -EEXIST;
            }
            else if (open_flags & O_NOFOLLOW)
            {
                st = -ELOOP;
            }
            else
            {
                /* If we can/should follow, follow the symlink */
                st = dentry_follow_symlink(data, data.cur,
                                           DENTRY_FOLLOW_SYMLINK_NOT_NAMEI_WALK_COMPONENT);

                if (st == 0)
                    st = 1; // 1 = caller should follow
            }

            goto out;
        }

        if ((path.trailing_slash() || open_flags & O_DIRECTORY) && !dentry_is_dir(data.cur))
        {
            st = -ENOTDIR;
            goto out;
        }

        if ((open_flags & (O_EXCL | O_CREAT)) == (O_EXCL | O_CREAT))
        {
            st = -EEXIST;
        }

        goto out;
    }

out:
    if (lockwrite)
        inode_unlock(curino);
    else
        inode_unlock_shared(curino);

    if (st == 0)
    {
        if (data.pdepth > 0)
        {
            data.pdepth--;
            st = 1;
        }
    }

    return st;
}

expected<file *, int> vfs_open(file *base, const char *name, unsigned int open_flags, mode_t mode)
{
    const unsigned int flags = open_flags & O_DIRECTORY ? LOOKUP_MUST_BE_DIR : 0;
    auto fs_root = get_filesystem_root();

    /* See the big comment in nameitests and https://lwn.net/Articles/926782/ */
    if ((open_flags & (O_DIRECTORY | O_CREAT)) == (O_DIRECTORY | O_CREAT))
        return unexpected{-EINVAL};

    dentry_get(fs_root->file->f_dentry);
    dentry_get(base->f_dentry);

    nameidata namedata{std::string_view{name, strlen(name)}, fs_root->file->f_dentry,
                       base->f_dentry};

    auto &pathname = namedata.paths[namedata.pdepth].view;

    auto pathname_length = pathname.length();

    if (pathname_length >= PATH_MAX)
        return unexpected<int>{-ENAMETOOLONG};
    if (pathname_length == 0)
        return unexpected<int>{-ENOENT};

    lookup_start(namedata);
    namedata.lookup_flags = flags | LOOKUP_DONT_DO_LAST_NAME;

    /* Start the actual lookup loop. */
    dentry *dent;
    int st = 0;

    for (;;)
    {
        st = namei_resolve_path(namedata);
        if (namedata.lookup_flags & LOOKUP_INTERNAL_SAW_LAST_NAME)
        {
            st = do_last_open(namedata, open_flags, mode);
            if (st <= 0)
                break;
        }
        else
            break;
    }

    if (st < 0)
    {
        dentry_put(namedata.cur);
        return unexpected<int>{st};
    }

    dent = namedata.cur;

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

static int do_lookup_parent_last(nameidata &data)
{
    dentry *cur = data.cur;
    inode *curino = cur->d_inode;
    int st = 0;
    auto &path = data.paths[data.pdepth];

    DCHECK(data.lookup_flags & LOOKUP_INTERNAL_SAW_LAST_NAME);
    data.lookup_flags &= ~LOOKUP_INTERNAL_SAW_LAST_NAME;

    inode_lock_shared(curino);

    auto last = get_token_from_path(path, true);
    DCHECK(last.data() != nullptr);

    st = namei_walk_component(last, data, NAMEI_UNLOCKED | NAMEI_NO_FOLLOW_SYM);

    if (st >= 0)
    {
        /* Ok, we found the last component, great. */
        /* Handle symlinks */
        if (dentry_is_symlink(data.cur))
        {
            if (data.lookup_flags & LOOKUP_FAIL_IF_LINK)
            {
                /* Annoying error code, but it's what mkdir requires... We dont have another caller
                 * of LOOKUP_FAIL_IF_LINK that's not mkdir, and -ELOOP can easily be confused with
                 * another symlink-related error (e.g exceeding nloops), so we can't easily convert
                 * -ELOOP to -EEXIST in mkdir_vfs. */
                st = -EEXIST;
                goto out;
            }

            if (!(data.lookup_flags & LOOKUP_NOFOLLOW) || path.trailing_slash())
            {
                /* If we can/should follow, follow the symlink.
                 * Since we are consuming this last token, re-call get_token_from_path.
                 */
                get_token_from_path(path, false);
                st = dentry_follow_symlink(data, data.cur,
                                           DENTRY_FOLLOW_SYMLINK_NOT_NAMEI_WALK_COMPONENT);

                if (st == 0)
                    st = 1; // 1 = caller should follow
                goto out;
            }
        }

        /* Not a symlink, use parent (cur = parent). */
        dentry_put(data.cur);
        DCHECK(data.parent);
        data.cur = data.parent;
        data.parent = nullptr;
    }
    else
    {
        /* Not found, no problem. We return -ENOENT. The caller will make sure to check if this
         * -ENOENT is actually a valid -ENOENT, or success. It can only be success if we end up
         * being the last name in the whole path, i.e it's not something like /brokensym/test where
         * we could get a false 0. */
        st = -ENOENT;
    }

out:
    inode_unlock_shared(curino);

    if (st == 0)
    {
        if (data.pdepth > 0)
        {
            data.pdepth--;
            st = 1;
        }
    }

    return st;
}

static expected<dentry *, int> namei_lookup_parent(dentry *base, const char *name,
                                                   unsigned int flags, struct path *outp)
{
    auto fs_root = get_filesystem_root();
    DCHECK(base != nullptr);

    dentry_get(fs_root->file->f_dentry);
    dentry_get(base);

    nameidata namedata{std::string_view{name, strlen(name)}, fs_root->file->f_dentry, base};

    auto &pathname = namedata.paths[namedata.pdepth].view;

    auto pathname_length = pathname.length();

    if (pathname_length >= PATH_MAX)
        return unexpected<int>{-ENAMETOOLONG};
    if (pathname_length == 0)
        return unexpected<int>{-ENOENT};

    lookup_start(namedata);
    namedata.lookup_flags = flags | LOOKUP_DONT_DO_LAST_NAME;

    /* Start the actual lookup loop. */
    dentry *dent;
    int st = 0;

    for (;;)
    {
        st = namei_resolve_path(namedata);
        if (namedata.lookup_flags & LOOKUP_INTERNAL_SAW_LAST_NAME)
        {
            st = do_lookup_parent_last(namedata);

            if (st == -ENOENT)
            {
                /* Translate the -ENOENT to a 0 if need be. See the comment in do_lookup_parent_last
                 */
                bool was_last_name = true;
                for (int i = namedata.pdepth; i >= 0; i--)
                {
                    if (namedata.paths[i].token_type != fs_token_type::LAST_NAME_IN_PATH)
                        was_last_name = false;
                }

                if (was_last_name)
                    st = 0;
            }

            if (st <= 0)
                break;
        }
        else
            break;
    }

    if (st < 0)
    {
        dentry_put(namedata.cur);
        return unexpected<int>{st};
    }

    dent = namedata.cur;
    DCHECK(dent != nullptr);
    *outp = namedata.paths[namedata.pdepth];

    return dent;
}

static expected<dentry *, int> namei_lookup_parentf(file *base, const char *name,
                                                    unsigned int flags, struct path *outp)
{
    return namei_lookup_parent(base->f_dentry, name, flags, outp);
}

struct file *open_vfs(struct file *dir, const char *path)
{
    return open_vfs_with_flags(dir, path, 0);
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

static expected<struct dentry *, int> namei_create_generic(struct dentry *base, const char *path,
                                                           mode_t mode, dev_t dev,
                                                           unsigned int extra_lookup_flags = 0)
{
    int st;
    struct path last_name;
    struct inode *inode = nullptr;
    unsigned int lookup_flags = NAMEI_ALLOW_NEGATIVE | extra_lookup_flags;

    auto ex = namei_lookup_parent(base, path, lookup_flags, &last_name);
    if (ex.has_error())
        return unexpected<int>{ex.error()};

    /* Ok, we have the directory, lock the inode and fetch the negative dentry */
    struct dentry *dir = ex.value();
    struct inode *dir_ino = dir->d_inode;
    inode_lock(dir_ino);

    auto name = get_token_from_path(last_name, false);
    struct dentry *dent = dentry_lookup_internal(name, dir, DENTRY_LOOKUP_UNLOCKED);
    if (!dent)
    {
        st = -errno;
        goto unlock_err;
    }

    if (!d_is_negative(dent))
    {
        st = -EEXIST;
        goto put_unlock_err;
    }

    if (!inode_can_access(dir_ino, FILE_ACCESS_WRITE))
    {
        st = -EACCES;
        goto put_unlock_err;
    }

    switch (mode & S_IFMT)
    {
        case S_IFREG:
            inode = dir_ino->i_fops->creat(dent, mode, dir);
            break;
        case S_IFDIR:
            inode = dir_ino->i_fops->mkdir(dent, mode, dir);
            break;
        case S_IFBLK:
        case S_IFCHR:
        case S_IFSOCK:
        case S_IFIFO:
            inode = dir_ino->i_fops->mknod(dent, mode, dev, dir);
            break;
        default:
            DCHECK(0);
    }

    if (!inode)
    {
        st = -errno;
        goto put_unlock_err;
    }

    d_positiveize(dent, inode);

    inode_unlock(dir_ino);
    dentry_put(dir);
    return dent;
put_unlock_err:
    dentry_put(dent);
unlock_err:
    inode_unlock(dir_ino);
    dentry_put(dir);
    return unexpected<int>{st};
}

expected<dentry *, int> creat_vfs(dentry *base, const char *path, int mode)
{
    // Mask out the possible file type bits and set IFREG for a regular creat
    mode &= ~S_IFMT;
    mode |= S_IFREG;
    return namei_create_generic(base, path, mode, 0);
}

#define S_IFBAD (~(S_IFDIR | S_IFCHR | S_IFBLK | S_IFREG | S_IFIFO | S_IFLNK | S_IFSOCK))

expected<dentry *, int> mknod_vfs(const char *path, mode_t mode, dev_t dev, struct dentry *dir)
{
    if (mode & S_IFMT & S_IFBAD)
        return unexpected<int>{-EINVAL};
    return namei_create_generic(dir, path, mode, 0);
}

expected<dentry *, int> mkdir_vfs(const char *path, mode_t mode, struct dentry *dir)
{
    mode &= ~S_IFMT;
    mode |= S_IFDIR;
    return namei_create_generic(dir, path, mode, 0, LOOKUP_FAIL_IF_LINK);
}

int symlink_vfs(const char *path, const char *dest, struct dentry *base)
{
    int st;
    struct path last_name;
    struct inode *inode = nullptr;
    unsigned int lookup_flags = NAMEI_ALLOW_NEGATIVE;

    auto ex = namei_lookup_parent(base, path, lookup_flags, &last_name);
    if (ex.has_error())
        return ex.error();

    /* Ok, we have the directory, lock the inode and fetch the negative dentry */
    struct dentry *dir = ex.value();
    struct inode *dir_ino = dir->d_inode;
    inode_lock(dir_ino);

    auto name = get_token_from_path(last_name, false);

    struct dentry *dent = dentry_lookup_internal(name, dir, DENTRY_LOOKUP_UNLOCKED);
    if (!dent)
    {
        st = -errno;
        goto unlock_err;
    }

    if (!d_is_negative(dent))
    {
        st = -EEXIST;
        goto put_unlock_err;
    }

    if (!inode_can_access(dir_ino, FILE_ACCESS_WRITE))
    {
        st = -EACCES;
        goto put_unlock_err;
    }

    inode = dir_ino->i_fops->symlink(dent, dest, dir);

    if (!inode)
    {
        st = -errno;
        goto put_unlock_err;
    }

    d_positiveize(dent, inode);

    inode_unlock(dir_ino);
    dentry_put(dir);
    dentry_put(dent);
    return 0;
put_unlock_err:
    dentry_put(dent);
unlock_err:
    inode_unlock(dir_ino);
    dentry_put(dir);
    return st;
}

int link_vfs(struct file *target, dentry *rel_base, const char *newpath)
{
    int st;
    struct path last_name;
    unsigned int lookup_flags = NAMEI_ALLOW_NEGATIVE;
    struct inode *dest_ino = target->f_ino;

    auto ex = namei_lookup_parent(rel_base, newpath, lookup_flags, &last_name);
    if (ex.has_error())
        return ex.error();

    /* Ok, we have the directory, lock the inode and fetch the negative dentry */
    struct dentry *dir = ex.value();
    struct inode *dir_ino = dir->d_inode;
    inode_lock(dir_ino);

    auto name = get_token_from_path(last_name, false);

    struct dentry *dent = dentry_lookup_internal(name, dir, DENTRY_LOOKUP_UNLOCKED);
    if (!dent)
    {
        st = -errno;
        goto unlock_err;
    }

    if (!d_is_negative(dent))
    {
        st = -EEXIST;
        goto put_unlock_err;
    }

    if (!inode_can_access(dir_ino, FILE_ACCESS_WRITE))
    {
        st = -EACCES;
        goto put_unlock_err;
    }

    if (dir_ino->i_dev != dest_ino->i_dev)
    {
        st = -EXDEV;
        goto put_unlock_err;
    }

    st = dir_ino->i_fops->link(target, dent->d_name, dir);

    if (st < 0)
    {
        st = -errno;
        goto put_unlock_err;
    }

    d_positiveize(dent, dest_ino);
    inode_inc_nlink(dest_ino);

    inode_unlock(dir_ino);
    dentry_put(dir);
    dentry_put(dent);
    return 0;
put_unlock_err:
    dentry_put(dent);
unlock_err:
    inode_unlock(dir_ino);
    dentry_put(dir);
    return st;
}

#define VALID_LINKAT_FLAGS (AT_SYMLINK_FOLLOW | AT_EMPTY_PATH)

int do_sys_link(int olddirfd, const char *uoldpath, int newdirfd, const char *unewpath, int flags)
{
    if (flags & ~VALID_LINKAT_FLAGS)
        return -EINVAL;

    unsigned int lookup_flags = LOOKUP_NOFOLLOW;

    if (flags & AT_EMPTY_PATH)
        lookup_flags |= LOOKUP_EMPTY_PATH;

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
        lookup_flags &= ~LOOKUP_NOFOLLOW;

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

int unlink_vfs(const char *path, int flags, struct file *node)
{
    int st = 0;
    struct path last_name;
    dentry *child = nullptr, *dentry = nullptr;
    inode *inode = nullptr;
    char _name[NAME_MAX + 1] = {};

    unsigned int lookup_flag = LOOKUP_NOFOLLOW;
    auto ex = namei_lookup_parentf(node, path, lookup_flag, &last_name);
    if (ex.has_error())
        return ex.error();

    auto name = get_token_from_path(last_name, false);
    if (!name.compare(".") || !name.compare(".."))
    {
        st = -EINVAL;
        goto out;
    }

    dentry = ex.value();
    inode = dentry->d_inode;

    if (!inode_can_access(inode, FILE_ACCESS_WRITE))
    {
        st = -EACCES;
        goto out;
    }

    memcpy(_name, name.data(), name.length());

    child = dentry_lookup_internal(name, dentry);
    if (!child)
    {
        st = -errno;
        goto out;
    }

    if (child)
    {
        if (d_is_negative(child))
        {
            st = -ENOENT;
            dentry_put(child);
            goto out;
        }
        /* Can't do that... Note that dentry always exists if it's a mountpoint */
        if (dentry_involved_with_mount(child))
            st = -EBUSY;

        /* Check if AT_REMOVEDIR and it's not a directory */
        if (flags & AT_REMOVEDIR && !dentry_is_dir(child))
            st = -ENOTDIR;

        if (st < 0)
        {
            dentry_put(child);
            goto out;
        }
    }

    rw_lock_write(&inode->i_rwlock);
    /* Do the actual fs unlink */
    st = inode->i_fops->unlink(_name, flags, dentry);

    if (st < 0)
    {
        goto out2;
    }

    /* The fs unlink succeeded! Lets change the dcache now that we can't fail! */
    if (child)
    {
        scoped_rwslock<rw_lock::write> g{dentry->d_lock};

        dentry_do_unlink(child);
    }

out2:
    rw_unlock_write(&inode->i_rwlock);

    /* Release the reference that we got from dentry_lookup_internal */
    if (child)
        dentry_put(child);
out:
    dentry_put(dentry);
    return st;
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

    return symlink_vfs(linkpath.data(), target.data(), dir.get_file()->f_dentry);
}

int sys_symlink(const char *target, const char *linkpath)
{
    return sys_symlinkat(target, AT_FDCWD, linkpath);
}

int do_renameat(struct dentry *dir, struct path &last, struct dentry *old)
{
    std::string_view name = get_token_from_path(last, false);
    if (!name.compare(".") || !name.compare(".."))
        return -EINVAL;
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
        return -EXDEV;

    if (old->d_inode == dir->d_inode)
        return -EINVAL;

    auto sb = inode->i_sb;

    if (!inode_can_access(inode, FILE_ACCESS_WRITE))
        return -EACCES;

    scoped_mutex rename_lock_guard{sb->s_rename_lock};

    char _name[NAME_MAX + 1] = {};
    memcpy(_name, name.data(), name.length());

    dentry *dest = dentry_lookup_internal(name, dir);
    if (!dest)
        return -ENOMEM;

    /* Can't do that... Note that dentry always exists if it's a mountpoint */
    if (dentry_involved_with_mount(dest))
    {
        dentry_put(dest);
        return -EBUSY;
    }

    scoped_rwlock<rw_lock::write> g{__dir1->d_inode->i_rwlock};
    scoped_rwlock<rw_lock::write> g2{__dir2->d_inode->i_rwlock};

    if (!d_is_negative(dest))
    {
        /* Case 2: dest inode = source inode */
        if (dest->d_inode == old->d_inode)
            return 0;

        /* Not sure if this is 100% correct */
        if (dentry_is_dir(old) ^ dentry_is_dir(dest))
        {
            dentry_put(dest);
            return -EISDIR;
        }
    }

    auto old_parent = __dentry_parent(old);

    if (!old_parent)
    {
        dentry_put(dest);
        return -ENOENT;
    }

    /* It's invalid to try to make a directory be a subdirectory of itself */
    if (!dentry_does_not_have_parent(dir, old))
    {
        dentry_put(dest);
        return -EINVAL;
    }

    /* Do the actual fs unlink(if dest exists) + link + unlink */
    /* The overall strategy here is to do everything that may fail first - so, for example,
     * everything that involves I/O or memory allocation. After that, we're left with the
     * bookkeeping, which can't fail.
     */
    int st = 0;

    // printk("Here3\n");

    if (!d_is_negative(dest))
    {
        /* Unlink the name on disk first */
        /* Note that i_fops->unlink() checks if the directory is empty, if it is one. */
        st = inode->i_fops->unlink(_name, AT_REMOVEDIR, dir);
    }

    // printk("(may have) unlinked\n");

    if (st < 0)
    {
        dentry_put(dest);
        return st;
    }

    struct file f;
    f.f_ino = old->d_inode;
    f.f_dentry = old;

    /* Now link the name on disk */
    st = inode->i_fops->link(&f, _name, dir);

    /* rename allows us to move a non-empty dir. Because of that we
     * pass a special flag (UNLINK_VFS_DONT_TEST_EMPTY) to the fs, that allows us to do
     * that.
     */
    st = old_parent->d_inode->i_fops->unlink(old->d_name, AT_REMOVEDIR | UNLINK_VFS_DONT_TEST_EMPTY,
                                             old_parent);

    // printk("done\n");

    /* TODO: What should we do if we fail in the middle? */
    if (st < 0)
    {
        dentry_put(dest);
        return st;
    }

    /* The fs unlink succeeded! Lets change the dcache now that we can't fail! */
    dentry_do_unlink(dest);

    /* TODO: Lacking atomicity */
    dentry_rename(old, _name, dir);

    return 0;
}

int sys_renameat(int olddirfd, const char *uoldpath, int newdirfd, const char *unewpath)
{
    auto_file olddir, newdir;
    user_string oldpath, newpath;
    struct path last_name;

    if (auto res = oldpath.from_user(uoldpath); res.has_error())
        return res.error();
    if (auto res = newpath.from_user(unewpath); res.has_error())
        return res.error();

    if (int st = olddir.from_dirfd(olddirfd); st < 0)
        return st;

    if (int st = newdir.from_dirfd(newdirfd); st < 0)
        return st;

    /* rename operates on the old and new symlinks and not their destination */
    auto_dentry old = dentry_do_open(olddir.get_file()->f_dentry, oldpath.data(), LOOKUP_NOFOLLOW);
    if (!old)
        return -errno;

    /* Although this doesn't need to be an error, we're considering it as one in the meanwhile
     */
    if (dentry_involved_with_mount(old.get_dentry()))
        return -EBUSY;

    if (!inode_can_access(old.get_dentry()->d_inode, FILE_ACCESS_WRITE))
        return -EACCES;

    unsigned int lookup_flag = LOOKUP_NOFOLLOW;
    auto ex = namei_lookup_parentf(newdir.get_file(), newpath.data(), lookup_flag, &last_name);
    if (ex.has_error())
        return ex.error();

    return do_renameat(ex.value(), last_name, old.get_dentry());
}

int sys_rename(const char *oldpath, const char *newpath)
{
    return sys_renameat(AT_FDCWD, oldpath, AT_FDCWD, newpath);
}

int sys_chroot(const char *upath)
{
    process *current;
    user_string path;
    if (auto res = path.from_user(upath); res.has_error())
        return res.error();
    if (!is_root_user())
        return -EPERM;

    auto ex = vfs_open(get_current_directory(), path.data(), O_RDONLY | O_DIRECTORY, 0000);
    if (ex.has_error())
        return ex.error();
    current = get_current_process();
    /* TODO: Solve root directory leaks (this is also racy!) */
    current->ctx.root->file = ex.value();
    return 0;
}
