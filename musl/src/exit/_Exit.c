#include <stdlib.h>
#include "syscall.h"

_Noreturn void _Exit(int ec)
{
	for (;;) __syscall(SYS_exit, ec);
}
