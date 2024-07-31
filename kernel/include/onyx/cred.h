/*
 * Copyright (c) 2020 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_CRED_H
#define _ONYX_CRED_H

#include <string.h>

#include <onyx/rwlock.h>
#include <onyx/types.h>

struct creds
{
    RWSLOCK lock;
    uid_t ruid;
    uid_t euid;
    gid_t rgid;
    gid_t egid;
    uid_t suid;
    uid_t sgid;
    // Type erasure because of C... Pain, all my homies know is pain.
    void *groups;
};

struct process;

__BEGIN_CDECLS

struct creds *creds_get(void);
struct creds *__creds_get(struct process *p);
struct creds *creds_get_write(void);
struct creds *__creds_get_write(struct process *p);
void creds_put(struct creds *c);
void creds_put_write(struct creds *c);

static inline bool is_root_user(void)
{
    struct creds *c = creds_get();

    bool is = c->euid == 0;

    creds_put(c);

    return is;
}

int process_inherit_creds(struct process *new_child, struct process *parent);

static inline void creds_init(struct creds *c)
{
    /* Hacky, but works for both C and C++ */
    memset(&c->ruid, 0, sizeof(*c) - offsetof(struct creds, ruid));
}

bool cred_is_in_group(struct creds *c, gid_t gid);

__END_CDECLS

#ifdef __cplusplus

#include <onyx/utility.hpp>

enum class CGType
{
    Write = 0,
    Read
};

template <CGType type = CGType::Read>
class creds_guard
{
    constexpr bool IsWrite() const
    {
        return type == CGType::Write;
    }

    creds *c;

public:
    constexpr creds_guard(creds *c) : c{c}
    {
    }

    creds_guard()
    {
        if (IsWrite())
            c = creds_get_write();
        else
            c = creds_get();
    }

    creds_guard(creds_guard &&g) : c{g.c}
    {
        g.c = nullptr;
    }

    creds_guard &operator=(creds_guard &&g)
    {
        c = g.c;
        g.c = nullptr;

        return *this;
    }

    CLASS_DISALLOW_COPY(creds_guard);

    ~creds_guard()
    {
        if (c)
        {
            if (IsWrite())
                creds_put_write(c);
            else
                creds_put(c);
        }
    }

    creds *get() const
    {
        return c;
    }
};

#endif

#endif
