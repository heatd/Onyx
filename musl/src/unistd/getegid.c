#include <unistd.h>
#include "syscall.h"
#include <onyx/public/cred.h>

gid_t getegid(void)
{
	gid_t egid;
	int st = onx_get_gids(NULL, &egid, NULL);
	return st < 0 ? st : egid;
}
