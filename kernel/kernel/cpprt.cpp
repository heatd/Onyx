/*
 * Copyright (c) 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
/********************************************************************************
 *
 *	File: cpprt.c
 *	Description: C++ runtime support
 *
 ********************************************************************************/
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <onyx/compiler.h>
#include <onyx/condvar.h>
#include <onyx/mutex.h>
#include <onyx/panic.h>

extern "C" {

/* Gets called when a virtual function isn't found */
USED_FUNC
void __cxa_pure_virtual(void)
{
    /* Just panic */
    panic("__cxa_pure_virtual: Virtual function not found!");
}
/* guard variables */

/* The ABI requires a 64-bit type.  */
using guard_type = int64_t;

// This should be constexpr
mutex guard_lock;
// This has no constructor
cond guard_cvar;

union guard_union {
    guard_type guard;
    char bytes[sizeof(guard_type)];
};

bool guard_is_initialised(guard_type *g)
{
    guard_union un = {*g};
    return un.bytes[0] != 0;
}

void guard_set_init(guard_type *g)
{
    guard_union un = {*g};
    un.bytes[0] = 1;
    *g = un.guard;
}

bool guard_is_locked(guard_type *g)
{
    guard_union un = {*g};
    return un.bytes[1] != 0;
}

void guard_do_lock(guard_type *g)
{
    guard_union un = {*g};
    un.bytes[1] = 1;
    *g = un.guard;
}

void guard_unlock(guard_type *g)
{
    guard_union un = {*g};
    un.bytes[1] = 0;
    *g = un.guard;
}

USED_FUNC
int __cxa_guard_acquire(guard_type *g)
{
    if (guard_is_initialised(g))
        return 0;

    mutex_lock(&guard_lock);

    while (guard_is_locked(g))
        condvar_wait(&guard_cvar, &guard_lock);

    bool result = guard_is_initialised(g);

    if (!result)
    {
        guard_do_lock(g);
    }

    mutex_unlock(&guard_lock);

    return !result;
}

USED_FUNC
void __cxa_guard_release(guard_type *g)
{
    scoped_mutex g_{guard_lock};

    guard_set_init(g);
    guard_unlock(g);
}

USED_FUNC
void __cxa_guard_abort(guard_type *g)
{
    *(char *)g = 0;
}
}

#ifdef CONFIG_KTEST_CXA_GUARD

#include <stdio.h>
#include <stdlib.h>

#include <libtest/libtest.h>

#include <onyx/atomic.hpp>
namespace cxa_guard_internal
{

class random_object
{
private:
    atomic<uint32_t> val;

public:
    random_object() : val{}
    {
    }

    void increment()
    {
        val++;
    }

    atomic<uint32_t> get_val()
    {
        return val;
    }
};

uint32_t very_cool_function(bool rw)
{
    static random_object static_obj;

    if (rw)
        static_obj.increment();
    else
        return static_obj.get_val();

    return 0;
}

void cxa_guard_thread_entry(void *arg)
{
    for (unsigned int i = 0; i < 0xffffffff; i++)
    {
        very_cool_function(false);
        COMPILER_BARRIER();
    }

    thread_exit();
}

bool cxa_guard_test(void)
{
    auto initial_value = very_cool_function(false);

    for (unsigned int i = 0; i < 4; i++)
    {
        auto thread = sched_create_thread(cxa_guard_thread_entry, THREAD_KERNEL, nullptr);

        assert(thread != nullptr);

        sched_start_thread(thread);
    }

    for (unsigned int i = 0; i < 0xffffffff; i++)
    {
        very_cool_function(true);
    }

    return very_cool_function(false) == initial_value + 0xffffffff;
}

DECLARE_TEST(cxa_guard_test, 4);

} // namespace cxa_guard_internal

#endif
