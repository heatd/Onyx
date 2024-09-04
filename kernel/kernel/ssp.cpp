/*
 * Copyright (c) 2016, 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */
/**************************************************************************
 *
 *
 * File: ssp.c
 *
 * Description: Contains the implementation of the GCC stack protector functions
 *
 * Date: 2/2/2016
 *
 *
 **************************************************************************/

#include <stdint.h>
#include <stdlib.h>

#include <onyx/compiler.h>
#include <onyx/internal_abi.h>
#include <onyx/panic.h>
#include <onyx/random.h>
#include <onyx/types.h>

#if UINT32_MAX == UINTPTR_MAX
#define STACK_CHK_GUARD 0xdeadc0de
#else
#define STACK_CHK_GUARD 0xdeadd00ddeadc0de
#endif

uintptr_t __stack_chk_guard = STACK_CHK_GUARD;

extern "C" __attribute__((noreturn, used)) void __stack_chk_fail()
{
    panic("Stack smashing detected");
}

namespace abi
{

unsigned long generate_stack_canary()
{
    unsigned long guard;
    arc4random_buf(&guard, sizeof(uintptr_t));
    return guard;
}

extern "C" __attribute__((used)) void init_ssp_for_cpu(unsigned int cpu_nr)
{
    static uintptr_t new_guard = generate_stack_canary();

    auto abi_details = get_abi_data();
    if (cpu_nr == 0)
        __stack_chk_guard = new_guard;

    abi_details->canary = new_guard;
}

} // namespace abi
