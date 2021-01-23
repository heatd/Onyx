#include <unistd.h>
#include "syscall.h"
#include "libc.h"

#include <onyx/public/cred.h>

int seteuid(uid_t euid)
{
	return onx_set_uids(SET_UIDS_EUID_VALID, -1, euid, -1);
}
