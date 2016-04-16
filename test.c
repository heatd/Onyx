#include <stdio.h>
#include <stdlib.h>
__attribute__((noinline))
volatile void module_step()
{
	abort();
}
int module_init()
{
	module_step();
	printf("Hello Module World! \n");
	while (1);
}
