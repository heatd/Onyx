/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <onyx/clock.h>
#include <onyx/compiler.h>
#include <onyx/dev.h>
#include <onyx/process.h>
#include <onyx/random.h>
#include <onyx/timer.h>

#include <drivers/rtc.h>

const size_t max_entropy = PAGE_SIZE * 4;
static char entropy_buffer[PAGE_SIZE * 4] = {};
struct mutex entropy_lock;
static size_t current_entropy = 0;

void add_entropy(void *ent, size_t size)
{
    scoped_lock g{entropy_lock};
    if (current_entropy == max_entropy || current_entropy + size > max_entropy)
    {
    }
    else
    {
        memcpy(&entropy_buffer[current_entropy], ent, size);
        current_entropy += size;
    }
}

void entropy_refill()
{
    unsigned int *buf = (unsigned int *) entropy_buffer;
    size_t nr_refills = max_entropy / sizeof(unsigned int);
    for (size_t i = 0; i < nr_refills; i++)
    {
        *buf++ =
            clock_get_posix_time() << 28 | ((entropy::platform::get_hwrandom() << 20) ^ rand());
    }

    current_entropy = max_entropy;
}

extern "C" void get_entropy(char *buf, size_t s)
{
    scoped_mutex g{entropy_lock};

    for (size_t i = 0; i < s; i++)
    {
        if (current_entropy == 0)
            entropy_refill();
        *buf++ = entropy_buffer[0];
        current_entropy--;
        memmove(entropy_buffer, &entropy_buffer[1], current_entropy);
    }
}

size_t ent_read(size_t off, size_t count, void *buffer, struct file *node)
{
    get_entropy((char *) buffer, count);
    return count;
}

void initialize_entropy(void)
{
    entropy::platform::init_random();
    /* Use get_posix_time as entropy, together with the platform's seed */
    uint64_t p = get_posix_time_early();
    add_entropy(&p, sizeof(uint64_t));
    auto seed = entropy::platform::get_seed();
    add_entropy(&seed, sizeof(uint64_t));
    srand((unsigned int) (seed | ~p));
    for (size_t i = current_entropy; i < max_entropy; i += sizeof(int))
    {
        int r = rand();
        add_entropy(&r, sizeof(int));
    }
}

size_t random_get_entropy(size_t size, void *buffer)
{
    unsigned char *buf = (unsigned char *) buffer;
    size_t to_read = size;
    while (to_read)
    {
        if (signal_is_pending())
            return -EINTR;

        if (current_entropy)
        {
            size_t r = current_entropy > to_read ? to_read : current_entropy;

            if (copy_to_user(buf, entropy_buffer, r) < 0)
                return -EFAULT;

            buf += r;
            to_read -= r;
        }
    }
    return size;
}

size_t urandom_get_entropy(size_t size, void *buffer)
{
    unsigned char *buf = (unsigned char *) buffer;
    size_t to_read = size;
    while (to_read)
    {
        if (signal_is_pending())
            return -EINTR;
        if (current_entropy)
        {
            size_t r = current_entropy > to_read ? to_read : current_entropy;

            if (copy_to_user(buf, entropy_buffer, r) < 0)
                return -EFAULT;

            buf += r;
            to_read -= r;
        }
        else
        {
            entropy_refill();
        }
    }
    return size;
}

size_t get_entropy_from_pool(int pool, size_t size, void *buffer)
{
    assert(pool == ENTROPY_POOL_RANDOM || pool == ENTROPY_POOL_URANDOM);
    size_t ret = (size_t) -EINVAL;

    scoped_mutex g{entropy_lock};

    switch (pool)
    {
        case ENTROPY_POOL_RANDOM: {
            ret = random_get_entropy(size, buffer);
            break;
        }

        case ENTROPY_POOL_URANDOM: {
            ret = urandom_get_entropy(size, buffer);
            break;
        }
    }

    return ret;
}

size_t random_read(size_t offset, size_t sizeofreading, void *buffer, struct file *f)
{
    return get_entropy_from_pool(ENTROPY_POOL_RANDOM, sizeofreading, buffer);
}

size_t urandom_read(size_t offset, size_t sizeofreading, void *buffer, struct file *f)
{
    return get_entropy_from_pool(ENTROPY_POOL_URANDOM, sizeofreading, buffer);
}

#define DEV_RANDOM_MINOR  0
#define DEV_URANDOM_MINOR 1

const file_ops random_fops = {.read = random_read};

const file_ops urandom_fops = {.read = urandom_read};

static chardev *random_dev, *urandom_dev;

static int init_random_dev(dev_t *major)
{
    auto ex = dev_register_chardevs(DEV_RANDOM_MINOR, 1, 0, &random_fops, cul::string{"random"});

    if (ex.has_error())
        return ex.error();

    random_dev = ex.value();
    random_dev->show(0666);
    *major = MAJOR(random_dev->dev());

    return 0;
}

static int init_urandom_dev(dev_t major_nr)
{
    auto ex = dev_register_chardevs(0, 1, 0, &urandom_fops, cul::string{"urandom"});
    if (ex.has_error())
        return ex.error();

    urandom_dev = ex.value();
    urandom_dev->show(0666);

    return 0;
}

void entropy_init_dev()
{
    // random registration is responsible for getting the major number for random and urandom
    // This is kind of not very pretty honestly...
    dev_t random_devs_major = 0;

    if (init_random_dev(&random_devs_major) < 0)
        return;

    init_urandom_dev(random_devs_major);
}

unsigned int get_random_int()
{
    auto num = entropy::platform::get_hwrandom();

    return (unsigned int) num ^ (num >> 32);
}

int sys_getrandom(void *buf, size_t buflen, unsigned int flags)
{
    return (int) get_entropy_from_pool(ENTROPY_POOL_URANDOM, buflen, buf);
}
