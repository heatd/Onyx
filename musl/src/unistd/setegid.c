#include <unistd.h>
#include "libc.h"
#include "syscall.h"

#include <onyx/public/cred.h>

int setegid(gid_t egid)
{
	return onx_set_gids(SET_GIDS_EGID_VALID, -1, egid, -1);
}
