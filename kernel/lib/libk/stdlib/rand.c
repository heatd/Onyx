#include <stdint.h>

int seed = 0x1A1A1A1A;
void srand(unsigned int s)
{
	seed = s & 0x7fffffff;
}
int rand_r(unsigned int *seed)
{
	// Else use an LCG
	*seed = ((*seed * 1103515245) + 123456) & 0x7fffffff;
	return (int) *seed;
}
int rand()
{
	return rand_r((unsigned int*) &seed);
}
