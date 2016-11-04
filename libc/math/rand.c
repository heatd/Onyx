#include <cpuid.h>
#include <immintrin.h>
#include <stdint.h>

int seed = 0x1A1A1A1A;
int rdrand_supported = INT32_MAX;
void srand(unsigned int s)
{
	seed = s & 0x7fffffff;
}
int rand_r(unsigned int *seed)
{
	if(rdrand_supported)
	{
		unsigned long long ret;
		_rdrand64_step(&ret);
		*seed = (unsigned int) ret;
		return (int)ret;
	}
	else
	{
		// Else use an LCG
		*seed = ((*seed * 1103515245) + 123456) & 0x7fffffff;
		return (int) *seed;
	}
}
int rand()
{
	if(rdrand_supported == INT32_MAX)
	{
		uint32_t eax,ebx,edx,ecx = 0;
		__get_cpuid(1,&eax,&ebx,&ecx,&edx);
		if(ecx & (1 << 30))
			rdrand_supported = 1;
	}
	return rand_r((unsigned int*) &seed);
}