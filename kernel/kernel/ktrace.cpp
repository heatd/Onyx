/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <errno.h>
#include <stdio.h>

#include <onyx/ktrace.h>
#include <onyx/modules.h>
#include <onyx/process.h>
#include <onyx/spinlock.h>
#include <onyx/symbol.h>

#include <onyx/hashtable.hpp>
#include <onyx/linker_section.hpp>
#include <onyx/memory.hpp>
#include <onyx/utility.hpp>

namespace ktrace
{

static struct spinlock tracepoint_lock;
static cul::hashtable<unique_ptr<ktracepoint>, 16, fnv_hash_t, ktracepoint::hash> tracepoint_list;

DEFINE_LINKER_SECTION_SYMS(__mcount_loc_start, __mcount_loc_end);
DEFINE_LINKER_SECTION_SYMS(__return_loc_start, __return_loc_end);

linker_section mcount_loc_section(&__mcount_loc_start, &__mcount_loc_end);
linker_section return_loc_section(&__return_loc_start, &__return_loc_end);

fnv_hash_t ktracepoint::hash(unique_ptr<ktracepoint> &p)
{
    return fnv_hash(&p->mcount_call_addr, sizeof(p->mcount_call_addr));
}

bool ktracepoint::find_call_addrs()
{
    mcount_call_addr = search_loc<mcount_loc_section>();
    return !(mcount_call_addr == search_bad_addr);
#if 0
	return_call_addr = search_loc<return_loc_section>();
	if(return_call_addr == search_bad_addr)
		return false;
#endif
}

bool append_tracepoint(unique_ptr<ktracepoint> &p)
{
    bool st = tracepoint_list.add_element(cul::move(p));

    return st;
}

int add_function(const char *func)
{
    struct symbol *s = module_resolve_sym(func);
    if (!s)
        return -EINVAL;

    scoped_lock g{tracepoint_lock};

    unique_ptr<ktracepoint> p = make_unique<ktracepoint>(func, s);
    if (!p)
    {
        return -ENOMEM;
    }

    /* Get the raw pointer to avoid having to search for it */
    ktracepoint *raw = p.get_data();

    if (!raw->find_call_addrs())
    {
        return false;
    }

    if (!raw->allocate_buffer())
    {
        return false;
    }

    if (!append_tracepoint(p))
    {
        return false;
    }

    raw->activate();

    return true;
}

void ktracepoint::put_entry(ktrace_ftrace_data &data)
{
    scoped_lock g{buf_lock};

    size_t off = write_pointer;

    if (off + sizeof(ktrace_ftrace_data) > ring_buffer_size)
    {
        /* Wrap around */
        off = write_pointer = 0;
    }

    if (off + sizeof(ktrace_ftrace_data) > read_pointer && off <= read_pointer)
    {
        nr_overruns++;
    }

    uint8_t *ptr = ((uint8_t *) PAGE_TO_VIRT(ring_buffer)) + off;
    memcpy(ptr, &data, sizeof(data));

    write_pointer += sizeof(data);
}

void ktracepoint::log_entry(unsigned long ip, unsigned long caller)
{
    (void) ip;
    ktrace_ftrace_data data;
    struct thread *current_thread = get_current_thread();
    struct process *curr_process = get_current_process();

    if (curr_process)
        data.pid = curr_process->get_pid();
    if (current_thread)
        data.tid = current_thread->id;
    data.timestamp = get_main_clock()->get_ns();
    data.type = KTRACE_TYPE_ENTRY;
    data.caller = caller;

    put_entry(data);
}

bool ktracepoint::allocate_buffer()
{
    ring_buffer = alloc_pages(pages2order(ring_buffer_size >> PAGE_SHIFT), PAGE_ALLOC_CONTIGUOUS);
    return ring_buffer != nullptr;
}

void log_func_entry(unsigned long ip, unsigned long caller)
{
    scoped_lock g{tracepoint_lock};

    auto it = tracepoint_list.get_hash_list_begin(fnv_hash(&ip, sizeof(ip)));
    auto end = tracepoint_list.get_hash_list_end(fnv_hash(&ip, sizeof(ip)));

    while (it != end)
    {
        auto &trace = *it;
        if (trace->get_entry_addr() == ip)
        {
            trace->log_entry(ip, caller);
            break;
        }

        it++;
    }
}

}; // namespace ktrace

void ktrace_init(void)
{
}
