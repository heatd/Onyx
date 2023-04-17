/*
 * Copyright (c) 2021 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _UAPI_CRED_H
#define _UAPI_CRED_H

#include <uapi/posix-types.h>

#define SET_UIDS_RUID_VALID (1 << 0)
#define SET_UIDS_EUID_VALID (1 << 1)
#define SET_UIDS_SUID_VALID (1 << 2)

#define SET_GIDS_RGID_VALID (1 << 0)
#define SET_GIDS_EGID_VALID (1 << 1)
#define SET_GIDS_SGID_VALID (1 << 2)

#ifdef __cplusplus
extern "C"
{
#endif

/* TODO: Don't expose these here. Also, get rid of this whole interface. */
int onx_get_uids(__uid_t *ruid, __uid_t *euid, __uid_t *suid);
int onx_get_gids(__gid_t *rgid, __gid_t *egid, __gid_t *sgid);

int onx_set_uids(unsigned int flags, __uid_t ruid, __uid_t euid, __uid_t suid);
int onx_set_gids(unsigned int flags, __gid_t rgid, __gid_t egid, __gid_t sgid);

#ifdef __cplusplus
}
#endif

#endif
