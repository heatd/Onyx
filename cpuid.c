#include <cpuid.h>

int main()
{
	unsigned int eax,ebx,ecx,edx;
	__get_cpuid(0,&eax,&ebx,&ecx,&edx);
	printf("0x%X\n",eax);
	return 0;
}
