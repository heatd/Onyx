
/*
 * Copyright (c) 2020 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_NAMEI_H
#define _ONYX_NAMEI_H

#include <onyx/dentry.h>
#include <onyx/limits.h>
#include <onyx/path.h>

#include <uapi/fcntl.h>

#include <onyx/string_view.hpp>

enum class fs_token_type : uint8_t
{
    REGULAR_TOKEN = 0,
    LAST_NAME_IN_PATH
};

#define LOOKUP_NOFOLLOW                (1 << 0)
#define LOOKUP_FAIL_IF_LINK            (1 << 1)
#define LOOKUP_MUST_BE_DIR             (1 << 2)
#define LOOKUP_INTERNAL_TRAILING_SLASH (1 << 3)
#define LOOKUP_EMPTY_PATH              (1 << 4)
#define LOOKUP_DONT_DO_LAST_NAME       (1 << 5)
#define LOOKUP_INTERNAL_SAW_LAST_NAME  (1U << 31)

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

expected<file *, int> vfs_open(int dirfd, const char *name, unsigned int open_flags, mode_t mode);

#endif
