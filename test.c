#include <stdio.h>
#include <stdlib.h>

int main()
{
	printf("Hello World");
	__asm__ __volatile__("movl $6,%eax \t\n int $0x80");
	return 0;
}
