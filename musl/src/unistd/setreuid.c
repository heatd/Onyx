#include <unistd.h>
#include "syscall.h"
#include "libc.h"

#include <onyx/public/cred.h>

int setreuid(uid_t ruid, uid_t euid)
{
	return onx_set_uids(SET_UIDS_RUID_VALID | SET_UIDS_EUID_VALID, ruid, euid, -1);
}
