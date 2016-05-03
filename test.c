#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main()
{
	asm volatile("movl $4, %eax\t\nint $0x80");

	while(1);
	return 0;
}
