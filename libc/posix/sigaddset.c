#include <errno.h>
#include <signal.h>

int sigaddset(sigset_t *set, int sig)
{
    unsigned s = sig - 1;
    if (s >= _NSIG - 1)
    {
        errno = EINVAL;
        return -1;
    }

    set->__bits[s / _NSIG_PER_WORD] |= (1 << (s % _NSIG_PER_WORD));
    return 0;
}
