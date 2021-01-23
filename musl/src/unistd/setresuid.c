#define _GNU_SOURCE
#include <unistd.h>
#include "syscall.h"
#include "libc.h"

#include <onyx/public/cred.h>

int setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	return onx_set_uids(SET_UIDS_EUID_VALID | SET_UIDS_RUID_VALID | SET_UIDS_SUID_VALID, ruid, euid, suid);
}
