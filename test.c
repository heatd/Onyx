#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
const char *msg = "[INIT] /usr/bin/daemon launched!\n";
int i = 0;
int main()
{
	//asm volatile("mov $4, %eax\t\nint $0x80");
	i = 5;
	while(1);
	if( i == 5)
		return 1;
	while(1);
	return 0;
}
