#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
const char *msg = "[INIT] /usr/bin/daemon launched!\n";
int main()
{
	asm volatile("mov $0, %%eax\t\nmov $1, %%ebx\t\nmov %0, %%ecx\t\nmov $26, %%edx\t\nint $0x80"::"r"(msg):"eax","ebx","ecx","edx");
	while(1);
	return 0;
}
