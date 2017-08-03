#include <features.h>
#include <string.h>
#define START "_start"

#include "crt_arch.h"

int main();
void _init() __attribute__((weak));
void _fini() __attribute__((weak));
_Noreturn int __libc_start_main(int (*)(), int, char **, char **, size_t *,
	void (*)(), void(*)(), void(*)());

void _start_c(int argc, char **argv, char **envp, size_t *auxv)
{
	__libc_start_main(main, argc, argv, envp, auxv, _init, _fini, 0);
}
