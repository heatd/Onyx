#include <signal.h>

int sigismember(const sigset_t *set, int sig)
{
	unsigned s = sig-1;
	if (s >= _NSIG-1) return 0;
	return set->__bits[s / _NSIG_PER_WORD] & (1 << (s % _NSIG_PER_WORD));
}
