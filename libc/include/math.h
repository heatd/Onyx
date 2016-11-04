#ifndef _MATH_STDLIB_H
#define _MATH_STDLIB_H
#ifdef __cplusplus
extern "C" {
#endif

long long int llabs(long long int i);
int rand();
int rand_r(unsigned int *seed);
void srand(unsigned int s);

#ifdef __cplusplus
}
#endif

#endif