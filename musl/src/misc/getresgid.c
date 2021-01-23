#define _GNU_SOURCE
#include <unistd.h>
#include "syscall.h"

#include <onyx/public/cred.h>

int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid)
{
	return onx_get_gids(rgid, egid, sgid);
}
