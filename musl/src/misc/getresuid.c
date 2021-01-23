#define _GNU_SOURCE
#include <unistd.h>
#include "syscall.h"

#include <onyx/public/cred.h>

int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid)
{
	return onx_get_uids(ruid, euid, suid);
}
