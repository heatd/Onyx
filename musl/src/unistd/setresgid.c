#define _GNU_SOURCE
#include <unistd.h>
#include "syscall.h"
#include "libc.h"

#include <onyx/public/cred.h>

int setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	return onx_set_gids(SET_GIDS_EGID_VALID | SET_GIDS_RGID_VALID | SET_GIDS_SGID_VALID, rgid, egid, sgid);
}
