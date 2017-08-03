#include <signal.h>
#include <stdint.h>
#include "syscall.h"
#include "pthread_impl.h"

int raise(int sig)
{
	int pid, ret;
	sigset_t set;
	(void) set;	
	/*__block_app_sigs(&set); */
	pid = __syscall(SYS_getpid);
	ret = syscall(SYS_kill, pid, sig);
	/*__restore_sigs(&set);*/
	return ret;
}
