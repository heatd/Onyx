#include <onyx/public/cred.h>
#include "syscall.h"

int onx_set_gids(unsigned int flags, gid_t rgid, gid_t egid, gid_t sgid)
{
	return syscall(SYS_set_gids, flags, rgid, egid, sgid);
}
