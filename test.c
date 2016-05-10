#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
volatile int i;
__attribute__ ((noinline)) void forked()
{
	int i;
	volatile char *h = &i;
	*h = 'c';
}
int main()
{
	asm volatile("movl $4, %eax\t\nint $0x80");
	register unsigned int eax asm("eax");
	printf("a");
	forked();
	while(1);
	return 0;
}
