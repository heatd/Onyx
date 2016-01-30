#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <kernel/tty.h>

void kernel_early()
{
	terminal_initialize();
}
void kernel_main()
{
	puts("Spartix 0.1");
}
