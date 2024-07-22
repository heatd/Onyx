/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */

#include <stdint.h>

int seed = 1;
void srand(unsigned int s)
{
    seed = (int) s;
}

int rand_r(unsigned int *seed)
{
    // Use an LCG
    *seed = ((*seed * 1103515245) + 123456);
    return (int) *seed;
}

int rand()
{
    return rand_r((unsigned int *) &seed);
}
