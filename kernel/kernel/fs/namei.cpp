/*
 * Copyright (c) 2020 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <onyx/cred.h>
#include <onyx/dentry.h>
#include <onyx/err.h>
#include <onyx/file.h>
#include <onyx/mount.h>
#include <onyx/namei.h>
#include <onyx/process.h>
#include <onyx/seqlock.h>
#include <onyx/user.h>
#include <onyx/vfs.h>

#include <uapi/fcntl.h>

#include <onyx/memory.hpp>

#ifdef CONFIG_DEBUG_NAMEI_TRACE_OPS
#define DEFINE_NAMEI_TRACE_HELPER(lowercase, uppercase)          \
    static inline void d_mark_##lowercase(struct dentry *dentry) \
    {                                                            \
        dentry->d_flags |= DENTRY_FLAG_##uppercase;              \
    }
#else
#define DEFINE_NAMEI_TRACE_HELPER(lowercase, uppercase)          \
    static inline void d_mark_##lowercase(struct dentry *dentry) \
    {                                                            \
    }
#endif

DEFINE_NAMEI_TRACE_HELPER(creat, CREAT);
DEFINE_NAMEI_TRACE_HELPER(unlink, UNLINK);
DEFINE_NAMEI_TRACE_HELPER(rename, RENAME);
DEFINE_NAMEI_TRACE_HELPER(link, LINK);
DEFINE_NAMEI_TRACE_HELPER(symlink, SYMLINK);

enum class fs_token_type : uint8_t
{
    REGULAR_TOKEN = 0,
    LAST_NAME_IN_PATH
};

/**
 * @brief Represents a path during a lookup
 *
 */
struct lookup_path
{
    std::string_view view;
    void *ownbuf{nullptr};
    fs_token_type token_type{fs_token_type::REGULAR_TOKEN};
    size_t pos{0};

    lookup_path() = default;

    lookup_path(std::string_view view) : view{view}
    {
    }

    constexpr bool trailing_slash() const
    {
        return view[view.length() - 1] == '/';
    }
};

struct nameidata
{
    /* Data needed to resolve filesystem names:
     * view - Contains the pathname;
     * pos - Contains the offset in the parsing of the pathname;
     * root - Contains the lookup's filesystem root;
     * cur - Contains the current relative location and
     * starts at whatever was passed as the relative dir (controlled with
     * chdir or *at, or purely through kernel-side use).
     */
    /* Note: root and location always hold a reference to the underlying object */
    struct path root;
    struct path cur;
    /* Keeps the parent of cur, *if* we walked once */
    struct path parent;

    static constexpr const size_t max_loops = SYMLOOP_MAX;
    /* Number of symbolic links found while looking up -
     * if it reaches max_symlinks, the lookup fails with -ELOOP.
     */
    int nloops{0};
    int pdepth{0};
    struct lookup_path paths[SYMLOOP_MAX];

    unsigned int lookup_flags{};
    int dirfd{AT_FDCWD};

    nameidata(std::string_view view)
    {
        paths[0] = lookup_path{view};
        path_init(&root);
        path_init(&cur);
        path_init(&parent);
    }

    ~nameidata();

    void setcur(struct path newcur)
    {
        DCHECK(!path_is_null(&newcur));
        path_put(&parent);
        parent = cur;
        cur = newcur;
    }

    path getcur()
    {
        DCHECK(!path_is_null(&cur));
        auto ret = cur;
        path_init(&cur);
        return ret;
    }
};

std::string_view get_token_from_path(lookup_path &path, bool no_consume_if_last)
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
    struct inode *ino = symlink->d_inode;
    struct path p = {symlink, data.cur.mount};

    if (!inode_can_access(ino, FILE_ACCESS_EXECUTE))
        return -EACCES;

    if (unlikely(ino->i_op->magic_jump))
        return ino->i_op->magic_jump(symlink, ino, &data);

    /* Oops - We hit the max symlink count */
    if (++data.nloops == nameidata::max_loops)
        return -ELOOP;

    auto target_str = readlink_vfs(&p);
    if (IS_ERR_OR_NULL(target_str))
        return !target_str ? -errno : PTR_ERR(target_str);

    /* Empty symlinks = -ENOENT. See nameitests for more info. */
    if (target_str[0] == '\0')
    {
        free(target_str);
        return -ENOENT;
    }

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
        path_put(&data.cur);
        data.cur = data.root;
        path_get(&data.cur);
    }
    else if (flags & DENTRY_FOLLOW_SYMLINK_NOT_NAMEI_WALK_COMPONENT)
    {
        path_put(&data.cur);
        data.cur = data.parent;
        path_init(&data.parent);
    }

    return 0;
}

#define NAMEI_UNLOCKED       (1U << 0)
#define NAMEI_NO_FOLLOW_SYM  (1U << 1)
#define NAMEI_ALLOW_NEGATIVE (1U << 2)

static void follow_mount_up(struct mount *mnt, struct path *out)
{
    struct dentry *dentry = mnt->mnt_root, *mountpoint;

    while (mnt->mnt_parent)
    {
        mountpoint = mnt->mnt_point;
        mnt = mnt->mnt_parent;
        if (mnt->mnt_root != dentry)
        {
            out->mount = mnt;
            out->dentry = mountpoint;
            return;
        }
    }

    /* Should not be hittable, I think... */
    CHECK(0);
}

static bool finish_mount_up(struct path *path, unsigned int seq)
{
    mnt_get(path->mount);
    smp_mb();

    if (path->mount->mnt_flags & MNT_DOOMED)
    {
        mnt_put(path->mount);
        goto retry;
    }

    /* I don't think there's a way this can fail, if we grabbed the mount itself */
    dget(path->dentry);

    if (read_seqretry(&mount_lock, seq))
        goto retry;

    return true;
retry:
    return false;
}

static int mount_dotdot(struct mount *mnt, struct path *path)
{
    rcu_read_lock();

    for (;;)
    {
        unsigned int seq = read_seqbegin(&mount_lock);
        follow_mount_up(mnt, path);

        /* Commit this follow_up by grabbing a reference to mount and mountpoint */
        if (finish_mount_up(path, seq))
            break;
    }

    rcu_read_unlock();
    return 0;
}

static int do_dotdot(nameidata &data, struct path *out)
{
    struct path *curr = &data.cur;
    if (curr->dentry == curr->mount->mnt_root)
    {
        /* We're the mount's root? Gotta take things in a different way. */
        return mount_dotdot(curr->mount, out);
    }

    struct dentry *dentry = dentry_parent(curr->dentry);
    if (!dentry)
    {
        /* /.. = right where we are */
        dentry = curr->dentry;
        dget(dentry);
        /* fallthrough */
    }

    struct path p = {dentry, curr->mount};
    mnt_get(curr->mount);
    *out = p;
    return 0;
}

static int __namei_walk_component(std::string_view v, nameidata &data, struct path *out,
                                  unsigned int flags)
{
    if (!v.compare("."))
    {
        *out = data.cur;
        path_get(out);
        return 0;
    }

    if (!v.compare(".."))
        return do_dotdot(data, out);

    struct dentry *dent = dentry_open_from_cache(data.cur.dentry, v);

    if (dent)
    {
        if (dent->d_flags & DENTRY_FLAG_PENDING)
            dent = dentry_wait_for_pending(dent);
    }

    if (!dent)
    {
        dent = __dentry_try_to_open(v, data.cur.dentry, !(flags & DENTRY_LOOKUP_UNLOCKED));
        if (!dent)
            return -errno;
    }

    struct path p = {.dentry = dent, .mount = data.cur.mount};
    mnt_get(data.cur.mount);
    *out = p;
    return 0;
}

static int namei_walk_component(std::string_view v, nameidata &data, unsigned int flags = 0)
{
    const bool is_last_name =
        data.paths[data.pdepth].token_type == fs_token_type::LAST_NAME_IN_PATH;
    const bool dont_follow_last = data.lookup_flags & LOOKUP_NOFOLLOW;
    const bool unlocked_lookup = flags & NAMEI_UNLOCKED;

    struct path path;
    file f;
    f.f_ino = data.cur.dentry->d_inode;

    if (!dentry_is_dir(data.cur.dentry))
        return -ENOTDIR;

    if (!file_can_access(&f, FILE_ACCESS_EXECUTE))
        return -EACCES;

    if (path_is_equal(&data.cur, &data.root) && !v.compare("..")) [[unlikely]]
    {
        /* Stop from escaping the chroot */
        return 0;
    }

    path_init(&path);
    int err = __namei_walk_component(v, data, &path, unlocked_lookup ? DENTRY_LOOKUP_UNLOCKED : 0);
    if (err < 0)
        return err;

#if 0
    pr_warn("Lookup %s found %p%s\n", v.data(), path.dentry,
            d_is_negative(path.dentry) ? " (negative)" : "");
#endif

    struct mount *mnt = path.mount;

    if (d_is_negative(path.dentry))
    {
        /* Check if the caller tolerates negative dentries as the lookup result. This only applies
         * for the last name. For !last_name, negative is always ENOENT */
        if (!is_last_name || !(flags & NAMEI_ALLOW_NEGATIVE))
        {
            err = -ENOENT;
            goto err_out;
        }
    }
    else if (dentry_is_symlink(path.dentry))
    {
        if (flags & NAMEI_NO_FOLLOW_SYM)
            goto out;
        /* POSIX states that paths that end in a trailing slash are required to be the same as
         * /. For example: open("/usr/bin/") == open("/usr/bin/."). Therefore, we have to
         * special case that.
         */

        const bool must_be_dir = data.paths[data.pdepth].trailing_slash();
        const bool should_follow_symlink = !dont_follow_last || must_be_dir;

        // printk("Following symlink for path elem %s\n", v.data());
        if (is_last_name && (data.lookup_flags & LOOKUP_FAIL_IF_LINK))
        {
            err = -ELOOP;
            goto err_out;
        }
        else if (is_last_name && !should_follow_symlink)
        {
            // printk("Cannot follow symlink. Trailing slash: %s\n", must_be_dir ? "yes" :
            // "no");
        }
        else [[likely]]
        {
            err = dentry_follow_symlink(data, path.dentry);
            path_put(&path);
            return err;
        }
    }
    else if (dentry_is_mountpoint(path.dentry))
    {
        struct mount *new_mount = mnt_traverse(path.dentry);
        if (new_mount)
        {
            struct dentry *d = new_mount->mnt_root;
            dget(d);
            mnt = new_mount;
            data.setcur((struct path){d, mnt});
            path_put(&path);
            return 0;
        }
    }

out:
    data.setcur(path);
    return 0;
err_out:
    path_put(&path);
    return err;
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
     * something akin to: open("/"), where the first slash was already consumed and now we're
     * left with an empty path; so return success.
     */
    if (data.paths[data.pdepth].view.length() == 0)
        return 0;

    for (;;)
    {
#define NAMEI_DEBUG 0
#if NAMEI_DEBUG
        pr_info("pdepth %d %s %s\n", data.pdepth, data.paths[data.pdepth].view.data(),
                data.paths[data.pdepth].token_type == fs_token_type::LAST_NAME_IN_PATH ? "last"
                                                                                       : "regular");
#endif
        auto &path = data.paths[data.pdepth];
        if (path.token_type == fs_token_type::LAST_NAME_IN_PATH)
        {
            if (path.trailing_slash())
            {
                // Check if we indeed opened a directory here
                if (!dentry_is_dir(data.cur.dentry))
                    return -ENOTDIR;
            }

            if (data.pdepth == 0)
                return 0;
            data.pdepth--;
            continue;
        }

        /* Get the next token from the path.
         * Note that it does not consume *if* this is the last token and the caller asked for us
         * not to do so.
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

        int st = namei_walk_component(v, data);
        if (st < 0)
            return st;
    }

    return 0;
}

[[nodiscard]] static int lookup_start(nameidata &data)
{
    auto &path = data.paths[data.pdepth];
    bool absolute = path.view[0] == '/';
    int offset = 0;
    DCHECK(path_is_null(&data.root));
    DCHECK(path_is_null(&data.cur));

    /* Note: get_filesystem_root() returns us a ref */
    data.root = get_filesystem_root();

    if (absolute)
    {
        data.cur = data.root;
        path_get(&data.root);
        while (path.view[offset] == '/')
            offset++;
    }
    else
    {
        /* Grab the CWD */
        int err = get_dirfd(data.dirfd, &data.cur);
        if (err < 0)
            return err;
    }

    path.view = std::string_view(&path.view[offset], path.view.length() - offset);
    return 0;
}

int namei_lookup(nameidata &data)
{
    auto &pathname = data.paths[data.pdepth].view;

    auto pathname_length = pathname.length();

    int st = lookup_start(data);
    if (st < 0)
        return st;

    if (pathname_length >= PATH_MAX)
        return -ENAMETOOLONG;
    if (pathname_length == 0)
    {
        if (data.lookup_flags & LOOKUP_EMPTY_PATH)
        {
            assert(!path_is_null(&data.cur));
            return 0;
        }

        return -ENOENT;
    }

    bool must_be_dir = data.lookup_flags & (LOOKUP_INTERNAL_TRAILING_SLASH | LOOKUP_MUST_BE_DIR);

    st = namei_resolve_path(data);
    if (st < 0)
        return st;

    if (!dentry_is_dir(data.cur.dentry) && must_be_dir)
        return -ENOTDIR;

    return 0;
}

nameidata::~nameidata()
{
    // Clean up
    path_put(&parent);
    path_put(&root);
    path_put(&cur);
}

static int dentry_resolve(nameidata &data, struct path *p)
{
    int st = namei_lookup(data);
    if (st < 0)
        return st;
    *p = data.getcur();
    return 0;
}

static int do_creat(dentry *dir, struct inode *inode, struct dentry *dentry, mode_t mode,
                    nameidata &data)
{
    int err;

    if (!inode_can_access(inode, FILE_ACCESS_WRITE))
        return -EACCES;

    if (data.lookup_flags & LOOKUP_INTERNAL_TRAILING_SLASH)
        return -ENOTDIR;

    DCHECK(d_is_negative(dentry));

    err = mnt_get_write_access(data.cur.mount);
    if (err)
        return err;

    struct inode *new_inode =
        inode->i_op->creat(dentry, do_umask((int) (mode & ~S_IFMT) | S_IFREG), dir);
    mnt_put_write(data.cur.mount);
    if (!new_inode)
        return -errno;

    d_positiveize(dentry, new_inode);
    d_mark_creat(dentry);
    return 0;
}

static int do_last_open(nameidata &data, int open_flags, mode_t mode)
{
    dentry *cur = data.cur.dentry;
    inode *curino = cur->d_inode;
    bool lockwrite = false;
    int st = 0;
    std::string_view last;
    auto &path = data.paths[data.pdepth];
    unsigned int lookup_flags = NAMEI_UNLOCKED | NAMEI_NO_FOLLOW_SYM;

    DCHECK(data.lookup_flags & LOOKUP_INTERNAL_SAW_LAST_NAME);

    data.lookup_flags &= ~LOOKUP_INTERNAL_SAW_LAST_NAME;

    if (lockwrite)
        inode_lock(curino);
    else
        inode_lock_shared(curino);

    last = get_token_from_path(path, false);
    DCHECK(last.data() != nullptr);

    if (open_flags & O_CREAT && path.trailing_slash())
    {
        st = -ENOTDIR;
        goto out;
    }

again:
    if (open_flags & O_CREAT && IS_DEADDIR(curino))
    {
        st = -ENOENT;
        goto out;
    }

    st = namei_walk_component(last, data, lookup_flags);

    if (st < 0 || (open_flags & O_CREAT && d_is_negative(data.cur.dentry)))
    {
        /* Failed to walk, try to creat if we can */
        if (!lockwrite && (open_flags & O_CREAT))
        {
            lockwrite = true;
            inode_unlock_shared(curino);
            inode_lock(curino);
            /* We want to get negative dentries too for O_CREAT, this time around */
            lookup_flags |= NAMEI_ALLOW_NEGATIVE;
            goto again;
        }

        if (open_flags & O_CREAT)
            st = do_creat(cur, curino, data.cur.dentry, mode, data);
    }
    else
    {
        /* Ok, we found the component, great. */
        /* First, handle symlinks */

        if (dentry_is_symlink(data.cur.dentry))
        {
            if ((open_flags & (O_EXCL | O_CREAT)) == (O_EXCL | O_CREAT))
            {
                /* If O_EXCL and O_CREAT are set, and path names a symbolic link, open() shall
                 * fail and set errno to [EEXIST], regardless of the contents of the symbolic
                 * link. */
                st = -EEXIST;
            }
            else if (open_flags & O_NOFOLLOW && !path.trailing_slash())
            {
                st = -ELOOP;
            }
            else
            {
                /* If we can/should follow, follow the symlink */
                st = dentry_follow_symlink(data, data.cur.dentry,
                                           DENTRY_FOLLOW_SYMLINK_NOT_NAMEI_WALK_COMPONENT);

                if (st == 0)
                    st = 1; // 1 = caller should follow
            }

            goto out;
        }

        if ((path.trailing_slash() || open_flags & O_DIRECTORY) && !dentry_is_dir(data.cur.dentry))
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

static bool may_noatime(file *f)
{
    creds_guard g;
    return g.get()->euid == 0 || f->f_ino->i_uid == g.get()->euid;
}

static expected<file *, int> complete_open(struct file *filp, unsigned int flags)
{
    /* Given a half-open (as in half-initialized) file, complete the open() per open(2) semantics */
    int err = 0;

    /* Let's check for permissions */
    if (!file_can_access(filp, open_to_file_access_flags(flags)))
    {
        err = -EACCES;
        goto err_free_half;
    }

    if (open_to_file_access_flags(flags) & FILE_ACCESS_WRITE)
    {
        err = mnt_get_write_access(filp->f_path.mount);
        if (err)
            goto err_free_half;
        filp->f_flags2 |= FILE_MNT_WRITE;
    }

    // O_NOATIME can only be used when the euid of the process = owner of file, or
    // when we're privileged (root).
    if (flags & O_NOATIME)
    {
        if (!may_noatime(filp))
        {
            err = -EPERM;
            goto err_free_half;
        }
    }

    if (S_ISDIR(filp->f_ino->i_mode))
    {
        if (flags & O_RDWR || flags & O_WRONLY || (flags & O_CREAT && !(flags & O_DIRECTORY)))
        {
            err = -EISDIR;
            goto err_free_half;
        }
    }

    filp->f_seek = 0;
    filp->f_flags = flags;
    filp->f_op = filp->f_ino->i_fops;
    filp->f_mapping = filp->f_ino->i_pages;

    /* Call the fops on_open. This is required before we call any filesystem methods. */
    if (filp->f_op->on_open)
    {
        err = filp->f_op->on_open(filp);
        if (err < 0)
            goto err_free_half;
    }

    if (flags & O_TRUNC)
    {
        int st = ftruncate_vfs(0, filp);
        if (st < 0)
        {
            fd_put(filp);
            return unexpected<int>{st};
        }
    }

    return filp;

err_free_half:
    if (filp->f_flags2 & FILE_MNT_WRITE)
        mnt_put_write(filp->f_path.mount);
    close_vfs(filp->f_ino);
    path_put(&filp->f_path);
    file_free(filp);
    return unexpected<int>{err};
}

expected<file *, int> vfs_open(int dirfd, const char *name, unsigned int open_flags, mode_t mode)
{
    const unsigned int flags = open_flags & O_DIRECTORY ? LOOKUP_MUST_BE_DIR : 0;

    /* See the big comment in nameitests and https://lwn.net/Articles/926782/ */
    if ((open_flags & (O_DIRECTORY | O_CREAT)) == (O_DIRECTORY | O_CREAT))
        return unexpected{-EINVAL};

    nameidata namedata{std::string_view{name, strlen(name)}};
    namedata.dirfd = dirfd;

    auto &pathname = namedata.paths[namedata.pdepth].view;
    auto pathname_length = pathname.length();

    if (pathname_length >= PATH_MAX)
        return unexpected<int>{-ENAMETOOLONG};
    if (pathname_length == 0)
        return unexpected<int>{-ENOENT};

    int st = lookup_start(namedata);
    if (st < 0)
        return unexpected<int>{st};

    namedata.lookup_flags = flags | LOOKUP_DONT_DO_LAST_NAME;

    /* Start the actual lookup loop. */
    struct path p;
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
        return unexpected<int>{st};

    p = namedata.getcur();

    auto new_file = inode_to_file(p.dentry->d_inode);
    if (!new_file)
    {
        path_put(&p);
        return nullptr;
    }

    inode_ref(p.dentry->d_inode);
    new_file->f_path = p;
    return complete_open(new_file, open_flags);
}

static bool lookup_was_last_name(nameidata &namedata)
{
    for (int i = namedata.pdepth; i >= 0; i--)
    {
        if (namedata.paths[i].token_type != fs_token_type::LAST_NAME_IN_PATH)
            return false;
    }

    return true;
}

static int do_lookup_parent_last(nameidata &data)
{
    dentry *cur = data.cur.dentry;
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
        if (dentry_is_symlink(data.cur.dentry))
        {
            if (data.lookup_flags & LOOKUP_FAIL_IF_LINK)
            {
                /* Annoying error code, but it's what mkdir requires... We dont have another
                 * caller of LOOKUP_FAIL_IF_LINK that's not mkdir, and -ELOOP can easily be
                 * confused with another symlink-related error (e.g exceeding nloops), so we
                 * can't easily convert -ELOOP to -EEXIST in mkdir_vfs. */
                st = -EEXIST;
                goto out;
            }

            if (!(data.lookup_flags & LOOKUP_NOFOLLOW) || path.trailing_slash())
            {
                /* If we can/should follow, follow the symlink.
                 * Since we are consuming this last token, re-call get_token_from_path.
                 */
                get_token_from_path(path, false);
                st = dentry_follow_symlink(data, data.cur.dentry,
                                           DENTRY_FOLLOW_SYMLINK_NOT_NAMEI_WALK_COMPONENT);

                if (st == 0)
                    st = 1; // 1 = caller should follow
                goto out;
            }
        }
    }
    else
    {
        /* Not found, no problem. We return -ENOENT. The caller will make sure to check if this
         * -ENOENT is actually a valid -ENOENT, or success. It can only be success if we end up
         * being the last name in the whole path, i.e it's not something like /brokensym/test
         * where we could get a false 0. */
        st = -ENOENT;
    }

out:
    inode_unlock_shared(curino);

    if (st == 0)
    {
        bool finished_path = true;
        for (int i = 0; i < data.pdepth; i++)
            if (data.paths[i].token_type != fs_token_type::LAST_NAME_IN_PATH)
                finished_path = false;
        if (finished_path)
            return 0;

        if (data.pdepth > 0)
        {
            data.pdepth--;
            st = 1;
        }
    }

    return st;
}

static int namei_lookup_parentat(int dirfd, const char *name, unsigned int flags,
                                 struct lookup_path *outn, struct path *parent)
{
    nameidata namedata{std::string_view{name, strlen(name)}};
    namedata.dirfd = dirfd;
    bool get_parent = true;
    auto &pathname = namedata.paths[namedata.pdepth].view;
    auto pathname_length = pathname.length();

    if (pathname_length >= PATH_MAX)
        return -ENAMETOOLONG;
    if (pathname_length == 0)
        return -ENOENT;

    int st = lookup_start(namedata);
    if (st < 0)
        return st;

    namedata.lookup_flags = flags | LOOKUP_DONT_DO_LAST_NAME;

    /* Start the actual lookup loop. */
    for (;;)
    {
        st = namei_resolve_path(namedata);
        if (namedata.lookup_flags & LOOKUP_INTERNAL_SAW_LAST_NAME)
        {
            st = do_lookup_parent_last(namedata);

            if (st == -ENOENT)
            {
                /* Translate the -ENOENT to a 0 if need be. See the comment in
                 * do_lookup_parent_last
                 */

                if (lookup_was_last_name(namedata))
                {
                    get_parent = false;
                    st = 0;
                }
            }

            if (st <= 0)
                break;
        }
        else
            break;
    }

    if (st < 0)
        return st;

    if (get_parent)
    {
        /* Use the parent of whatever we got. */
        path_put(&namedata.cur);
        DCHECK(!path_is_null(&namedata.parent));
        namedata.cur = namedata.parent;
        path_init(&namedata.parent);
    }

    DCHECK(!path_is_null(&namedata.cur));
    *outn = namedata.paths[namedata.pdepth];
    *parent = namedata.getcur();
    return 0;
}

/* Helper to open specific dentries */
dentry *dentry_do_open(int dirfd, const char *path, unsigned int lookup_flags = 0)
{
    nameidata namedata{std::string_view{path, strlen(path)}};
    namedata.dirfd = dirfd;
    namedata.lookup_flags = lookup_flags;
    struct path p;

    int err = dentry_resolve(namedata, &p);
    if (err < 0)
        return errno = err, nullptr;
    if (p.mount)
        mnt_put(p.mount);
    return p.dentry;
}

static expected<struct dentry *, int> namei_create_generic(int dirfd, const char *path, mode_t mode,
                                                           dev_t dev,
                                                           unsigned int extra_lookup_flags = 0)
{
    int st;
    struct lookup_path last_name;
    struct inode *inode = nullptr;
    unsigned int lookup_flags = NAMEI_ALLOW_NEGATIVE | extra_lookup_flags;
    struct path parent;

    st = namei_lookup_parentat(dirfd, path, lookup_flags, &last_name, &parent);
    if (st < 0)
        return unexpected<int>{st};

    /* Ok, we have the directory, lock the inode and fetch the negative dentry */
    struct dentry *dir = parent.dentry;
    struct inode *dir_ino = dir->d_inode;
    struct dentry *dent = NULL;
    inode_lock(dir_ino);

    auto name = get_token_from_path(last_name, false);

    if (IS_DEADDIR(dir_ino))
    {
        st = -ENOENT;
        goto unlock_err;
    }

    dent = dentry_lookup_internal(name, dir, DENTRY_LOOKUP_UNLOCKED);
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

    st = mnt_get_write_access(parent.mount);
    if (st)
        goto put_unlock_err;

    mode = do_umask(mode);
    switch (mode & S_IFMT)
    {
        case S_IFREG:
            inode = dir_ino->i_op->creat(dent, mode, dir);
            break;
        case S_IFDIR:
            inode = dir_ino->i_op->mkdir(dent, mode, dir);
            break;
        case S_IFBLK:
        case S_IFCHR:
        case S_IFSOCK:
        case S_IFIFO:
            inode = dir_ino->i_op->mknod(dent, mode, dev, dir);
            break;
        default:
            DCHECK(0);
    }

    mnt_put_write(parent.mount);

    if (!inode)
    {
        st = -errno;
        goto put_unlock_err;
    }

    d_positiveize(dent, inode);
    d_mark_creat(dent);

    inode_unlock(dir_ino);
    path_put(&parent);
    return dent;
put_unlock_err:
    dput(dent);
unlock_err:
    inode_unlock(dir_ino);
    path_put(&parent);
    return unexpected<int>{st};
}

#define S_IFBAD (~(S_IFDIR | S_IFCHR | S_IFBLK | S_IFREG | S_IFIFO | S_IFLNK | S_IFSOCK))

expected<dentry *, int> mknod_vfs(const char *path, mode_t mode, dev_t dev, int dirfd)
{
    if (mode & S_IFMT & S_IFBAD)
        return unexpected<int>{-EINVAL};
    return namei_create_generic(dirfd, path, mode, dev);
}

expected<dentry *, int> mkdir_vfs(const char *path, mode_t mode, int dirfd)
{
    mode &= ~S_IFMT;
    mode |= S_IFDIR;
    return namei_create_generic(dirfd, path, mode, 0, LOOKUP_FAIL_IF_LINK);
}

int symlink_vfs(const char *path, const char *dest, int dirfd)
{
    int st;
    struct lookup_path last_name;
    struct inode *inode = nullptr;
    unsigned int lookup_flags = LOOKUP_NOFOLLOW | NAMEI_ALLOW_NEGATIVE;
    struct path parent;

    st = namei_lookup_parentat(dirfd, path, lookup_flags, &last_name, &parent);
    if (st < 0)
        return st;

    /* Ok, we have the directory, lock the inode and fetch the negative dentry */
    struct dentry *dir = parent.dentry;
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

    st = mnt_get_write_access(parent.mount);
    if (st)
        goto put_unlock_err;

    inode = dir_ino->i_op->symlink(dent, dest, dir);
    mnt_put_write(parent.mount);
    if (!inode)
    {
        st = -errno;
        goto put_unlock_err;
    }

    d_positiveize(dent, inode);
    d_mark_symlink(dent);

    inode_unlock(dir_ino);
    path_put(&parent);
    dput(dent);
    return 0;
put_unlock_err:
    dput(dent);
unlock_err:
    inode_unlock(dir_ino);
    path_put(&parent);
    return st;
}

int link_vfs(struct dentry *target, int dirfd, const char *newpath)
{
    int st;
    struct lookup_path last_name;
    unsigned int lookup_flags = NAMEI_ALLOW_NEGATIVE;
    struct inode *dest_ino = target->d_inode;
    struct path parent;

    st = namei_lookup_parentat(dirfd, newpath, lookup_flags, &last_name, &parent);
    if (st < 0)
        return st;

    /* Ok, we have the directory, lock the inode and fetch the negative dentry */
    struct dentry *dir = parent.dentry;
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

    st = mnt_get_write_access(parent.mount);
    if (st)
        goto put_unlock_err;

    st = dir_ino->i_op->link(target, dent);
    mnt_put_write(parent.mount);
    if (st < 0)
    {
        st = -errno;
        goto put_unlock_err;
    }

    inode_ref(dest_ino);
    d_positiveize(dent, dest_ino);
    d_mark_link(dent);
    inode_inc_nlink(dest_ino);
    inode_update_ctime(dest_ino);

    inode_unlock(dir_ino);
    path_put(&parent);
    dput(dent);
    return 0;
put_unlock_err:
    dput(dent);
unlock_err:
    inode_unlock(dir_ino);
    path_put(&parent);
    return st;
}

#define VALID_LINKAT_FLAGS (AT_SYMLINK_FOLLOW | AT_EMPTY_PATH)

int do_sys_link(int olddirfd, const char *uoldpath, int newdirfd, const char *unewpath, int flags)
{
    int err;
    struct path path;
    unsigned int lookup_flags = LOOKUP_NOFOLLOW;

    if (flags & ~VALID_LINKAT_FLAGS)
        return -EINVAL;

    if (flags & AT_EMPTY_PATH)
        lookup_flags |= LOOKUP_EMPTY_PATH;

    user_string oldpath, newpath;

    if (auto res = oldpath.from_user(uoldpath); !res.has_value())
        return res.error();

    if (auto res = newpath.from_user(unewpath); !res.has_value())
        return res.error();

    if (flags & AT_SYMLINK_FOLLOW)
        lookup_flags &= ~LOOKUP_NOFOLLOW;

    err = path_openat(olddirfd, oldpath.data(), lookup_flags, &path);
    if (err)
        return err;

    if (dentry_is_dir(path.dentry))
    {
        path_put(&path);
        return -EPERM;
    }

    err = link_vfs(path.dentry, newdirfd, newpath.data());
    path_put(&path);
    return err;
}

int sys_link(const char *oldpath, const char *newpath)
{
    return do_sys_link(AT_FDCWD, oldpath, AT_FDCWD, newpath, 0);
}

int sys_linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags)
{
    return do_sys_link(olddirfd, oldpath, newdirfd, newpath, flags);
}

int unlink_vfs(const char *path, int flags, int dirfd)
{
    int st = 0;
    struct lookup_path last_name;
    struct path parent;
    dentry *child = nullptr, *dentry = nullptr;
    inode *inode = nullptr;
    char _name[NAME_MAX + 1] = {};

    unsigned int lookup_flag = LOOKUP_NOFOLLOW;
    st = namei_lookup_parentat(dirfd, path, lookup_flag, &last_name, &parent);
    if (st < 0)
        return st;

    auto name = get_token_from_path(last_name, false);
    if (!name.compare(".") || !name.compare(".."))
    {
        st = -EINVAL;
        goto out;
    }

    dentry = parent.dentry;
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
            dput(child);
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
            dput(child);
            goto out;
        }
    }

    st = mnt_get_write_access(parent.mount);
    if (st)
        goto out;

    rw_lock_write(&inode->i_rwlock);
    /* Do the actual fs unlink */
    st = inode->i_op->unlink(_name, flags, dentry);

    if (st < 0)
    {
        goto out2;
    }
    d_mark_unlink(child);

    /* The fs unlink succeeded! Lets change the dcache now that we can't fail! */
    if (child)
    {
        spin_lock(&dentry->d_lock);
        dentry_do_unlink(child);
        spin_unlock(&dentry->d_lock);
        if (dentry_is_dir(child))
        {
            child->d_inode->i_flags |= I_DEADDIR;
            dentry_shrink_subtree(child);
        }
    }

out2:
    mnt_put_write(parent.mount);
    rw_unlock_write(&inode->i_rwlock);

    /* Release the reference that we got from dentry_lookup_internal */
    if (child)
        dput(child);
out:
    path_put(&parent);
    return st;
}

#define VALID_UNLINKAT_FLAGS AT_REMOVEDIR

int do_sys_unlink(int dirfd, const char *upathname, int flags)
{
    auto_file dir;
    user_string pathname;

    if (flags & ~VALID_UNLINKAT_FLAGS)
        return -EINVAL;

    if (auto res = pathname.from_user(upathname); !res.has_value())
        return res.error();
    return unlink_vfs(pathname.data(), flags, dirfd);
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
    user_string target, linkpath;

    if (auto res = target.from_user(utarget); !res.has_value())
        return res.error();
    if (auto res = linkpath.from_user(ulinkpath); !res.has_value())
        return res.error();

    return symlink_vfs(linkpath.data(), target.data(), newdirfd);
}

int sys_symlink(const char *target, const char *linkpath)
{
    return sys_symlinkat(target, AT_FDCWD, linkpath);
}

int do_renameat(struct dentry *dir, struct lookup_path &last, struct dentry *old)
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
        dput(dest);
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
            dput(dest);
            return -EISDIR;
        }
    }

    auto old_parent = __dentry_parent(old);

    if (!old_parent)
    {
        dput(dest);
        return -ENOENT;
    }

    /* It's invalid to try to make a directory be a subdirectory of itself */
    if (!dentry_does_not_have_parent(dir, old))
    {
        dput(dest);
        dput(old_parent);
        return -EINVAL;
    }

    if (IS_DEADDIR(inode))
    {
        dput(dest);
        dput(old_parent);
        return -ENOENT;
    }
    /* Do the actual fs rename */
    /* The overall strategy here is to do everything that may fail first - so, for example,
     * everything that involves I/O or memory allocation. After that, we're left with the
     * bookkeeping, which can't fail.
     */
    int st = 0;
    if (old->d_inode->i_op->rename)
        st = old->d_inode->i_op->rename(old_parent, old, dir, dest);
    else
        st = -EOPNOTSUPP;

    if (st < 0)
    {
        dput(dest);
        dput(old_parent);
        return st;
    }

    d_mark_rename(old);
    d_mark_rename(dir);
    d_mark_rename(dest);

    dentry_rename(old, _name, dir, dest);
    dput(dest);
    dput(old_parent);
    return 0;
}

int sys_renameat(int olddirfd, const char *uoldpath, int newdirfd, const char *unewpath)
{
    user_string oldpath, newpath;
    struct lookup_path last_name;
    struct path old;
    struct path parent;
    int st;

    if (auto res = oldpath.from_user(uoldpath); res.has_error())
        return res.error();
    if (auto res = newpath.from_user(unewpath); res.has_error())
        return res.error();

    /* rename operates on the old and new symlinks and not their destination */
    st = path_openat(olddirfd, oldpath.data(), LOOKUP_NOFOLLOW, &old);
    if (st < 0)
        return st;

    /* Although this doesn't need to be an error, we're considering it as one in the meanwhile
     */
    st = -EBUSY;
    if (dentry_involved_with_mount(old.dentry))
        goto out_put_old;

    st = -EACCES;
    if (!inode_can_access(old.dentry->d_inode, FILE_ACCESS_WRITE))
        goto out_put_old;

    st = mnt_get_write_access(old.mount);
    if (st)
        goto out_put_old;

    st = namei_lookup_parentat(newdirfd, newpath.data(), LOOKUP_NOFOLLOW, &last_name, &parent);
    if (st < 0)
        return st;

    st = mnt_get_write_access(parent.mount);
    if (st < 0)
        goto out_put;

    st = do_renameat(parent.dentry, last_name, old.dentry);
    mnt_put_write(parent.mount);
out_put:
    path_put(&parent);
    mnt_put_write(old.mount);
out_put_old:
    path_put(&old);
    return st;
}

int sys_rename(const char *oldpath, const char *newpath)
{
    return sys_renameat(AT_FDCWD, oldpath, AT_FDCWD, newpath);
}

int sys_chroot(const char *upath)
{
    process *current;
    user_string path;
    struct path root, old;
    if (auto res = path.from_user(upath); res.has_error())
        return res.error();
    if (!is_root_user())
        return -EPERM;

    int err = path_openat(AT_FDCWD, path.data(), LOOKUP_MUST_BE_DIR, &root);
    if (err < 0)
        return err;
    current = get_current_process();
    struct fsctx *ctx = current->fs;

    spin_lock(&ctx->cwd_lock);
    /* We drop the ref *after* the lock is dropped */
    old = ctx->root;
    ctx->root = root;
    spin_unlock(&ctx->cwd_lock);
    path_put(&old);

    return 0;
}

int path_openat(int dirfd, const char *name, unsigned int flags, struct path *path)
{
    nameidata namedata{std::string_view{name, strlen(name)}};
    namedata.lookup_flags = flags;
    namedata.dirfd = dirfd;

    int err = namei_lookup(namedata);
    if (err < 0)
        return err;

    *path = namedata.getcur();
    return 0;
}

extern "C" struct file *c_vfs_open(int dirfd, const char *name, unsigned int open_flags,
                                   mode_t mode)
{
    auto ex = vfs_open(dirfd, name, open_flags, mode);
    return ex.has_value() ? ex.value() : (struct file *) ERR_PTR(ex.error());
}

static int namei_create_generic_path(int dirfd, const char *path, mode_t mode, dev_t dev,
                                     struct path *out, unsigned int extra_lookup_flags = 0)
{
    int st;
    struct lookup_path last_name;
    struct inode *inode = nullptr;
    unsigned int lookup_flags = NAMEI_ALLOW_NEGATIVE | extra_lookup_flags;
    struct path parent;

    st = namei_lookup_parentat(dirfd, path, lookup_flags, &last_name, &parent);
    if (st < 0)
        return st;

    /* Ok, we have the directory, lock the inode and fetch the negative dentry */
    struct dentry *dir = parent.dentry;
    struct inode *dir_ino = dir->d_inode;
    struct dentry *dent = NULL;
    inode_lock(dir_ino);

    auto name = get_token_from_path(last_name, false);

    if (IS_DEADDIR(dir_ino))
    {
        st = -ENOENT;
        goto unlock_err;
    }

    dent = dentry_lookup_internal(name, dir, DENTRY_LOOKUP_UNLOCKED);
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

    st = mnt_get_write_access(parent.mount);
    if (st)
        goto put_unlock_err;

    mode = do_umask(mode);
    switch (mode & S_IFMT)
    {
        case S_IFREG:
            inode = dir_ino->i_op->creat(dent, mode, dir);
            break;
        case S_IFDIR:
            inode = dir_ino->i_op->mkdir(dent, mode, dir);
            break;
        case S_IFBLK:
        case S_IFCHR:
        case S_IFSOCK:
        case S_IFIFO:
            inode = dir_ino->i_op->mknod(dent, mode, dev, dir);
            break;
        default:
            DCHECK(0);
    }

    mnt_put_write(parent.mount);

    if (!inode)
    {
        st = -errno;
        goto put_unlock_err;
    }

    d_positiveize(dent, inode);
    d_mark_creat(dent);

    inode_unlock(dir_ino);
    dput(parent.dentry);
    parent.dentry = dent;
    *out = parent;
    /* No need to put the parent path, we've just put the parent dentry, and we reuse the mnt
     * reference */
    return 0;
put_unlock_err:
    dput(dent);
unlock_err:
    inode_unlock(dir_ino);
    path_put(&parent);
    return st;
}

int mknodat_path(int dirfd, const char *path, mode_t mode, dev_t dev, struct path *out)
{
    if (mode & S_IFMT & S_IFBAD)
        return -EINVAL;
    return namei_create_generic_path(dirfd, path, mode, 0, out);
}

void namei_jump(struct nameidata *data, struct path *path)
{
    path_put(&data->cur);
    data->cur = *path;
}
