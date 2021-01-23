#include <onyx/public/cred.h>
#include "syscall.h"

int onx_get_gids(gid_t *rgid, gid_t *egid, gid_t *sgid)
{
	return syscall(SYS_get_gids, rgid, egid, sgid);
}
