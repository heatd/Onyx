/*
 * Copyright (c) 2020, 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <errno.h>

#include <onyx/compiler.h>
#include <onyx/cred.h>
#include <onyx/process.h>
#include <onyx/public/cred.h>

static struct creds kernel_creds = {
    .lock = rwlock{}, .ruid = 0, .euid = 0, .rgid = 0, .egid = 0, .suid = 0, .sgid = 0};

static struct creds *get_default_creds(void)
{
    struct process *p = get_current_process();
    struct creds *c = &kernel_creds;
    if (likely(p))
    {
        c = &p->cred;
    }

    return c;
}

struct creds *creds_get(void)
{
    struct creds *c = get_default_creds();

    rw_lock_read(&c->lock);
    return c;
}

struct creds *creds_get_write(void)
{
    struct creds *c = get_default_creds();

    rw_lock_write(&c->lock);
    return c;
}

void creds_put(struct creds *c)
{
    rw_unlock_read(&c->lock);
}

void creds_put_write(struct creds *c)
{
    rw_unlock_write(&c->lock);
}

struct creds *__creds_get(struct process *p)
{
    struct creds *c = &p->cred;

    rw_lock_read(&c->lock);
    return c;
}

struct creds *__creds_get_write(struct process *p)
{
    struct creds *c = &p->cred;

    rw_lock_write(&c->lock);
    return c;
}

int process_inherit_creds(struct process *new_child, struct process *parent)
{
    /* FIXME: Setuid and setgid? */
    struct creds *parentc = &parent->cred;

    new_child->cred.egid = parentc->egid;
    new_child->cred.rgid = parentc->rgid;
    new_child->cred.euid = parentc->euid;
    new_child->cred.ruid = parentc->ruid;
    /* FIXME: Implement sgid and suid */
    new_child->cred.sgid = new_child->cred.suid = 0;

    return 0;
}

int sys_setuid(uid_t uid)
{
    int st = 0;
    struct creds *c = creds_get_write();

    if (c->euid != 0 && (uid != c->ruid && uid != c->suid))
    {
        st = -EPERM;
        goto out;
    }

    if (c->euid == 0)
    {
        c->euid = uid;
        c->ruid = uid;
        c->suid = uid;
    }
    else
    {
        if (uid != c->ruid && uid != c->suid)
        {
            st = -EPERM;
            goto out;
            return -EPERM;
        }

        c->euid = uid;
    }

out:
    creds_put_write(c);

    return st;
}

int sys_setgid(gid_t gid)
{
    int st = 0;
    struct creds *c = creds_get_write();

    if (c->egid != 0 && (gid != c->rgid && gid != c->sgid))
    {
        st = -EPERM;
        goto out;
    }

    if (c->egid == 0)
    {
        c->egid = gid;
        c->rgid = gid;
        c->sgid = gid;
    }
    else
    {
        if (gid != c->rgid && gid != c->sgid)
        {
            st = -EPERM;
            goto out;
        }

        c->egid = gid;
    }

out:
    creds_put_write(c);

    return st;
}

uid_t sys_getuid(void)
{
    struct creds *c = creds_get();

    uid_t u = c->euid;

    creds_put(c);

    return u;
}

gid_t sys_getgid(void)
{
    struct creds *c = creds_get();

    gid_t g = c->egid;

    creds_put(c);

    return g;
}

int sys_get_uids(uid_t *ruid, uid_t *euid, uid_t *suid)
{
    creds_guard<CGType::Read> g;
    auto c = g.get();

    if (ruid && copy_to_user(ruid, &c->ruid, sizeof(uid_t)) < 0)
        return -EFAULT;

    if (euid && copy_to_user(euid, &c->euid, sizeof(uid_t)) < 0)
        return -EFAULT;

    if (suid && copy_to_user(suid, &c->suid, sizeof(uid_t)) < 0)
        return -EFAULT;

    return 0;
}

int sys_get_gids(gid_t *rgid, gid_t *egid, gid_t *sgid)
{
    creds_guard<CGType::Read> g;
    auto c = g.get();

    if (rgid && copy_to_user(rgid, &c->rgid, sizeof(gid_t)) < 0)
        return -EFAULT;

    if (egid && copy_to_user(egid, &c->egid, sizeof(gid_t)) < 0)
        return -EFAULT;

    if (sgid && copy_to_user(sgid, &c->sgid, sizeof(gid_t)) < 0)
        return -EFAULT;

    return 0;
}

bool may_switch_to_uid(uid_t id, creds *c)
{
    return id == c->euid || id == c->ruid || id == c->suid;
}

#define SET_UIDS_RUID_VALID (1 << 0)
#define SET_UIDS_EUID_VALID (1 << 1)
#define SET_UIDS_SUID_VALID (1 << 2)

int sys_set_uids(unsigned int flags, uid_t ruid, uid_t euid, uid_t suid)
{
    creds_guard<CGType::Write> g;

    /* We check for -1 because it's an invalid uid and POSIX uses it in
     * setresuid to signal a UID that shouldn't be changed.
     */
    bool euid_valid = flags & SET_UIDS_EUID_VALID && euid != (uid_t) -1;
    bool ruid_valid = flags & SET_UIDS_RUID_VALID && ruid != (uid_t) -1;
    bool suid_valid = flags & SET_UIDS_SUID_VALID && suid != (uid_t) -1;

    auto c = g.get();

    if (c->euid != 0)
    {
        /* If euid != root, ruid, euid and suid may only be one of the current (r/e/s) uids */
        if ((euid_valid && !may_switch_to_uid(euid, c)) ||
            (ruid_valid && !may_switch_to_uid(ruid, c)) ||
            (suid_valid && !may_switch_to_uid(suid, c)))
            return -EPERM;
    }

    if (euid_valid)
        c->euid = euid;
    if (ruid_valid)
        c->ruid = ruid;
    if (suid_valid)
        c->suid = suid;

    return 0;
}

bool may_switch_to_gid(gid_t id, creds *c)
{
    return id == c->egid || id == c->rgid || id == c->sgid;
}

int sys_set_gids(unsigned int flags, gid_t rgid, gid_t egid, gid_t sgid)
{
    creds_guard<CGType::Write> g;

    /* We check for -1 because it's an invalid uid and POSIX uses it in
     * setresuid to signal a GID that shouldn't be changed.
     */

    bool egid_valid = flags & SET_GIDS_EGID_VALID && egid != (gid_t) -1;
    bool rgid_valid = flags & SET_GIDS_RGID_VALID && rgid != (gid_t) -1;
    bool sgid_valid = flags & SET_GIDS_SGID_VALID && sgid != (gid_t) -1;

    auto c = g.get();

    if (c->euid != 0)
    {
        /* If egid != root, rgid, egid and sgid may only be one of the current (r/e/s) gids */
        if ((egid_valid && !may_switch_to_gid(egid, c)) ||
            (rgid_valid && !may_switch_to_gid(rgid, c)) ||
            (sgid_valid && !may_switch_to_gid(sgid, c)))
            return -EPERM;
    }

    if (egid_valid)
        c->egid = egid;
    if (rgid_valid)
        c->rgid = rgid;
    if (sgid_valid)
        c->sgid = sgid;

    return 0;
}

int supp_groups::set_groups(const gid_t *u_gid_list, size_t size)
{
    if (!groups.resize(size))
        return -ENOMEM;

    if (copy_from_user(&groups.front(), u_gid_list, size * sizeof(gid_t)) < 0)
        return -EFAULT;

    groups.set_nr_elems(size);

    return 0;
}

int supp_groups::get_groups(int _size, gid_t *ugids)
{
    size_t size = (size_t) _size;
    if (size == 0)
    {
        /* When size = 0, getgroups returns the size of the supplementary group list */
        return groups.size();
    }

    if (size != groups.size())
        return -EINVAL;

    if (copy_to_user(ugids, &groups.front(), size * sizeof(gid_t)) < 0)
        return -EFAULT;

    return 0;
}

/* TODO: Implement set/getresuid, set/getresgid, set/getgroups */
int sys_setgroups(size_t size, const gid_t *ugids)
{
    creds_guard<CGType::Write> g;
    auto c = g.get();

    if (c->euid != 0)
        return -EPERM;

    if (size > INT_MAX)
        return -EINVAL;

    if (ugids == nullptr)
    {
        /* Drop the current groups */
        reinterpret_cast<supp_groups *>(c->groups)->unref();
        c->groups = nullptr;
        return 0;
    }

    auto groups = new supp_groups;
    if (!groups)
        return -ENOMEM;

    if (int st = groups->set_groups(ugids, size); st < 0)
    {
        groups->unref();
        return st;
    }

    /* ew */
    cul::swap(groups, *reinterpret_cast<supp_groups **>(&c->groups));
    if (groups)
        groups->unref();

    return 0;
}

int sys_getgroups(int size, gid_t *ugids)
{
    if (size < 0)
        return -EINVAL;

    creds_guard<CGType::Read> g;
    auto c = g.get();

    supp_groups *grps = reinterpret_cast<supp_groups *>(c->groups);
    if (!grps)
        return 0;
    /* We don't need to increment a refcount here since we hold the creds lock */

    return grps->get_groups(size, ugids);
}

bool cred_is_in_group(struct creds *c, gid_t gid)
{
    supp_groups *grps = reinterpret_cast<supp_groups *>(c->groups);
    if (!grps)
        return false;

    auto &ids = grps->ids();

    for (const auto &g : ids)
    {
        if (g == gid)
            return true;
    }

    return false;
}
