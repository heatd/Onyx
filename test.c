#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
volatile int i;
int main()
{
	asm volatile("movl $4, %eax\t\nint $0x80");

	i = 5;
	if(i == 5)
	{
		return 0;
	}
	while(1);
	return 0;
}
