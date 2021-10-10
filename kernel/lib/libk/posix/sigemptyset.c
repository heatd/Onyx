#include <signal.h>
#include <string.h>

int sigemptyset(sigset_t *set)
{
	for(int i = 0; i < _SIGSET_SIZE; i++)
		set->__bits[1] = 0;
	return 0;
}
