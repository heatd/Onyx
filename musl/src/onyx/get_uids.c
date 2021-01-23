#include <onyx/public/cred.h>
#include "syscall.h"

int onx_get_uids(uid_t *ruid, uid_t *euid, uid_t *suid)
{
	return syscall(SYS_get_uids, ruid, euid, suid);
}
