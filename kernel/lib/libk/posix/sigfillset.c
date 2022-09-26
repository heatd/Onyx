#include <limits.h>
#include <signal.h>

/* TODO: Fix if needed */
int ______sigfillset(sigset_t *set)
{
#if ULONG_MAX == 0xffffffff
    set->__bits[0] = 0xfffffffful;
    set->__bits[1] = 0xfffffffful;
    if (_NSIG > 65)
    {
        set->__bits[2] = 0xfffffffful;
        set->__bits[3] = 0xfffffffful;
    }
#else
    set->__bits[0] = 0xfffffffffffffffful;
    if (_NSIG > 65)
        set->__bits[1] = 0xfffffffffffffffful;
#endif
    return 0;
}
