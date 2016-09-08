#include <cpuid.h>
#include <immintrin.h>
#include <stdint.h>
int rand()
{
	#ifndef _STDC_HOSTED
	uint32_t eax,ebx,edx,ecx = 0;
	__get_cpuid(1,&eax,&ebx,&ecx,&edx);
	if(ecx & (1 << 30))
	{
		unsigned long long ret;
		_rdrand64_step(&ret);
		return (int)ret;
	}
	#endif
	return 0;
}