/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */
#ifndef _ONYX_CPUMASK_H
#define _ONYX_CPUMASK_H

#include <string.h>

struct cpumask
{
#define LONG_SIZE_BITS __LONG_WIDTH__
#define CPUMASK_SIZE   CONFIG_SMP_NR_CPUS / LONG_SIZE_BITS
    unsigned long mask[CPUMASK_SIZE];

#ifdef __cplusplus
    constexpr cpumask() : mask{}
    {
    }

    constexpr void set_cpu(unsigned long cpu)
    {
        auto long_idx = cpu / LONG_SIZE_BITS;
        auto bit_idx = cpu % LONG_SIZE_BITS;

        mask[long_idx] |= (1UL << bit_idx);
    }

    void set_cpu_atomic(unsigned long cpu)
    {
        auto long_idx = cpu / LONG_SIZE_BITS;
        auto bit_idx = cpu % LONG_SIZE_BITS;

        __atomic_or_fetch(&mask[long_idx], (1UL << bit_idx), __ATOMIC_RELAXED);
    }

    constexpr void remove_cpu(unsigned long cpu)
    {
        auto long_idx = cpu / LONG_SIZE_BITS;
        auto bit_idx = cpu % LONG_SIZE_BITS;

        mask[long_idx] &= ~(1UL << bit_idx);
    }

    void remove_cpu_atomic(unsigned long cpu)
    {
        auto long_idx = cpu / LONG_SIZE_BITS;
        auto bit_idx = cpu % LONG_SIZE_BITS;

        __atomic_and_fetch(&mask[long_idx], ~(1UL << bit_idx), __ATOMIC_RELAXED);
    }

    constexpr bool is_cpu_set(unsigned long cpu) const
    {
        auto long_idx = cpu / LONG_SIZE_BITS;
        auto bit_idx = cpu % LONG_SIZE_BITS;

        return mask[long_idx] & (1UL << bit_idx);
    }

    constexpr cpumask& operator|=(unsigned long cpu)
    {
        set_cpu(cpu);

        return *this;
    }

    constexpr cpumask& operator|=(const cpumask& rhs)
    {
        for (unsigned long i = 0; i < CPUMASK_SIZE; i++)
        {
            mask[i] |= rhs.mask[i];
        }

        return *this;
    }

    constexpr cpumask operator|(const cpumask& rhs) const
    {
        cpumask m{*this};
        return m |= rhs;
    }

    constexpr cpumask operator~()
    {
        cpumask m{*this};

        for (unsigned long i = 0; i < CPUMASK_SIZE; i++)
        {
            m.mask[i] = ~m.mask[i];
        }

        return m;
    }

    constexpr cpumask& operator&=(const cpumask& rhs)
    {
        for (unsigned long i = 0; i < CPUMASK_SIZE; i++)
        {
            mask[i] &= rhs.mask[i];
        }

        return *this;
    }

    constexpr cpumask operator&(const cpumask& rhs) const
    {
        cpumask m{*this};
        return m &= rhs;
    }

    constexpr cpumask& operator^=(const cpumask& rhs)
    {
        for (unsigned long i = 0; i < CPUMASK_SIZE; i++)
        {
            mask[i] ^= rhs.mask[i];
        }

        return *this;
    }

    constexpr cpumask operator^(const cpumask& rhs) const
    {
        cpumask m{*this};

        return m ^= rhs;
    }

    template <typename Callable>
    void for_every_cpu(Callable c)
    {
        for (unsigned long i = 0; i < CPUMASK_SIZE; i++)
        {
            int curr_bit = -1;

            auto word = mask[i];

            /* Nothing to look at here */
            if (word == 0)
                continue;

            while (true)
            {
                if (curr_bit >= 0)
                {
                    /* Remove from the input the current bit and the bits before it */
                    word &= ~(1UL << curr_bit);
                }

                if (word == 0)
                    break;
                /* The word == 0 case has already been dealt with before this */
                curr_bit = __builtin_ffsl(word) - 1;

                auto cpu = LONG_SIZE_BITS * i + curr_bit;

                if (!c(cpu))
                    return;
            }
        }
    }

    static constexpr cpumask all()
    {
        return ~cpumask{};
    }

    static constexpr cpumask all_but_one(unsigned long cpu)
    {
        cpumask m;
        m.set_cpu(cpu);
        return ~m;
    }

    static constexpr cpumask one(unsigned long cpu)
    {
        cpumask m;
        m.set_cpu(cpu);
        return m;
    }

    unsigned long* raw_mask()
    {
        return mask;
    }

    constexpr bool is_empty() const
    {
        for (const auto& v : mask)
        {
            if (v != 0)
                return false;
        }

        return true;
    }
#endif
};

static inline struct cpumask cpumask_all_but_one(unsigned long cpu)
{
    struct cpumask c;
    memset((void*) &c, 0xff, sizeof(c));
    c.mask[cpu / LONG_SIZE_BITS] &= ~(1UL << (cpu % LONG_SIZE_BITS));
    return c;
}

static inline void cpumask_set_atomic(struct cpumask* mask, unsigned long cpu)
{
    unsigned long long_idx = cpu / LONG_SIZE_BITS;
    unsigned long bit_idx = cpu % LONG_SIZE_BITS;

    __atomic_or_fetch(&mask->mask[long_idx], (1UL << bit_idx), __ATOMIC_RELAXED);
}

static inline void cpumask_unset_atomic(struct cpumask* mask, unsigned long cpu)
{
    unsigned long long_idx = cpu / LONG_SIZE_BITS;
    unsigned long bit_idx = cpu % LONG_SIZE_BITS;

    __atomic_and_fetch(&mask->mask[long_idx], ~(1UL << bit_idx), __ATOMIC_RELAXED);
}

static inline bool cpumask_is_set(struct cpumask* mask, unsigned long cpu)
{
    unsigned long long_idx = cpu / LONG_SIZE_BITS;
    unsigned long bit_idx = cpu % LONG_SIZE_BITS;
    return mask->mask[long_idx] & (1UL << bit_idx);
}

#endif
