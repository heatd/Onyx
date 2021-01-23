/*
* Copyright (c) 2021 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_PUBLIC_CRED_H
#define _ONYX_PUBLIC_CRED_H

#include <sys/types.h>

#define SET_UIDS_RUID_VALID   (1 << 0)
#define SET_UIDS_EUID_VALID   (1 << 1)
#define SET_UIDS_SUID_VALID   (1 << 2)

#define SET_GIDS_RGID_VALID   (1 << 0)
#define SET_GIDS_EGID_VALID   (1 << 1)
#define SET_GIDS_SGID_VALID   (1 << 2)

#ifdef __cplusplus
extern "C" {
#endif

int onx_get_uids(uid_t *ruid, uid_t *euid, uid_t *suid);
int onx_get_gids(gid_t *rgid, gid_t *egid, gid_t *sgid);

int onx_set_uids(unsigned int flags, uid_t ruid, uid_t euid, uid_t suid);
int onx_set_gids(unsigned int flags, gid_t rgid, gid_t egid, gid_t sgid);


#ifdef __cplusplus
}
#endif

#endif
