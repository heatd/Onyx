#include <onyx/public/cred.h>
#include "syscall.h"

int onx_set_uids(unsigned int flags, uid_t ruid, uid_t euid, uid_t suid)
{
	return syscall(SYS_set_uids, flags, ruid, euid, suid);
}
