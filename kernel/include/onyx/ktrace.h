/*
 * Copyright (c) 2020 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_KTRACE_H
#define _ONYX_KTRACE_H

#include <onyx/page.h>
#include <onyx/process.h>
#include <onyx/symbol.h>
#include <onyx/timer.h>
#include <onyx/vm.h>

void ktrace_init(void);

enum ktrace_type_entry
{
    KTRACE_TYPE_ENTRY = 0,
    KTRACE_TYPE_EXIT = 1
};

struct ktrace_ftrace_data
{
    unsigned int tid;
    pid_t pid;
    unsigned long caller;
    hrtime_t timestamp;
    enum ktrace_type_entry type;
} __attribute__((packed));

#ifdef __cplusplus

#include <onyx/linker_section.hpp>
#include <onyx/memory.hpp>

namespace ktrace
{

class old_broken_ktracepoint
{
private:
    const char *function_name;
    struct page *ring_buffer;
    static constexpr size_t ring_buffer_size = PAGE_SIZE * 8;
    size_t read_pointer;
    size_t write_pointer;
    unsigned long nr_overruns;
    struct spinlock buf_lock;
    bool activated;
    struct symbol *sym;
    unsigned long mcount_call_addr;
    unsigned long return_call_addr;

    static constexpr unsigned long search_bad_addr = -1;

    template <linker_section &section>
    unsigned long search_loc()
    {
        auto locs = section.as<unsigned long>();
        size_t loc_entries = section.size() / sizeof(unsigned long);

        for (size_t i = 0; i < loc_entries; i++)
        {
            if (locs[i] >= sym->value && locs[i] < sym->value + sym->size)
                return locs[i];
        }

        return search_bad_addr;
    }
    void put_entry(ktrace_ftrace_data &data);

public:
    unsigned long get_entry_addr()
    {
        return mcount_call_addr;
    }

    old_broken_ktracepoint(const char *function_name, struct symbol *sym)
        : function_name(function_name), ring_buffer{nullptr}, read_pointer{0}, write_pointer{0},
          nr_overruns{0}, buf_lock{}, sym(sym), mcount_call_addr{}, return_call_addr{}
    {
    }

    bool find_call_addrs();
    bool allocate_buffer();

    void activate();
    void deactivate();
    void log_entry(unsigned long ip, unsigned long caller);

    static fnv_hash_t hash(unique_ptr<old_broken_ktracepoint> &t);
};

void log_func_entry(unsigned long ip, unsigned long caller);

}; // namespace ktrace

#endif

#endif
