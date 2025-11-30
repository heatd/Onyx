/*
 * Copyright (c) 2020 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <errno.h>
#include <stdio.h>

#include <onyx/dentry.h>
#include <onyx/dev.h>
#include <onyx/init.h>
#include <onyx/ktrace.h>
#include <onyx/modules.h>
#include <onyx/process.h>
#include <onyx/spinlock.h>
#include <onyx/static_key.h>
#include <onyx/symbol.h>
#include <onyx/trace/trace_base.h>
#include <onyx/trace/tracing_buffer.h>
#include <onyx/user.h>

#include <uapi/ktrace.h>

#include <onyx/hashtable.hpp>
#include <onyx/linker_section.hpp>
#include <onyx/memory.hpp>
#include <onyx/utility.hpp>

namespace ktrace
{

static struct spinlock old_broken_ktracepoint_lock;
static cul::hashtable<unique_ptr<old_broken_ktracepoint>, 16, fnv_hash_t,
                      old_broken_ktracepoint::hash>
    old_broken_ktracepoint_list;

DEFINE_LINKER_SECTION_SYMS(__mcount_loc_start, __mcount_loc_end);
DEFINE_LINKER_SECTION_SYMS(__return_loc_start, __return_loc_end);

DEFINE_LINKER_SECTION_SYMS(__data_trace_start, __data_trace_end);

linker_section mcount_loc_section(&__mcount_loc_start, &__mcount_loc_end);
linker_section return_loc_section(&__return_loc_start, &__return_loc_end);

linker_section trace_event_section(&__data_trace_start, &__data_trace_end);

void assign_unique_evid()
{
    u16 evid = 0;
    trace_event *it = trace_event_section.as<trace_event>();
    trace_event *end =
        trace_event_section.as<trace_event>() + (trace_event_section.size() / sizeof(trace_event));

    while (it != end)
    {
        it->evid = evid++;
        it++;
    }
}

trace_event *find_event_by_name(const char *name)
{
    std::string_view view{name};

    auto dot = view.find('.');
    DCHECK(dot != view.npos);
    std::string_view category = view.substr(0, dot);
    std::string_view event_name = view.substr(dot + 1);

    trace_event *it = trace_event_section.as<trace_event>();
    trace_event *end =
        trace_event_section.as<trace_event>() + (trace_event_section.size() / sizeof(trace_event));

    while (it != end)
    {
        if (category == it->category && event_name == it->name)
            return it;
        it++;
    }

    return nullptr;
}

trace_event *find_event(u32 evid)
{
    trace_event *it = trace_event_section.as<trace_event>();
    trace_event *end =
        trace_event_section.as<trace_event>() + (trace_event_section.size() / sizeof(trace_event));

    while (it != end)
    {
        if (it->evid == evid)
            return it;
        it++;
    }

    return nullptr;
}

fnv_hash_t old_broken_ktracepoint::hash(unique_ptr<old_broken_ktracepoint> &p)
{
    return fnv_hash(&p->mcount_call_addr, sizeof(p->mcount_call_addr));
}

bool old_broken_ktracepoint::find_call_addrs()
{
    mcount_call_addr = search_loc<mcount_loc_section>();
    return !(mcount_call_addr == search_bad_addr);
#if 0
	return_call_addr = search_loc<return_loc_section>();
	if(return_call_addr == search_bad_addr)
		return false;
#endif
}

bool append_tracepoint(unique_ptr<old_broken_ktracepoint> &p)
{
    bool st = old_broken_ktracepoint_list.add_element(cul::move(p));

    return st;
}

int add_function(const char *func)
{
    struct symbol *s = module_resolve_sym(func);
    if (!s)
        return -EINVAL;

    scoped_lock g{old_broken_ktracepoint_lock};

    unique_ptr<old_broken_ktracepoint> p = make_unique<old_broken_ktracepoint>(func, s);
    if (!p)
    {
        return -ENOMEM;
    }

    /* Get the raw pointer to avoid having to search for it */
    old_broken_ktracepoint *raw = p.get_data();

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

void old_broken_ktracepoint::put_entry(ktrace_ftrace_data &data)
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

void old_broken_ktracepoint::log_entry(unsigned long ip, unsigned long caller)
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

bool old_broken_ktracepoint::allocate_buffer()
{
    ring_buffer = alloc_pages(pages2order(ring_buffer_size >> PAGE_SHIFT), PAGE_ALLOC_CONTIGUOUS);
    return ring_buffer != nullptr;
}

void log_func_entry(unsigned long ip, unsigned long caller)
{
    scoped_lock g{old_broken_ktracepoint_lock};

    auto it = old_broken_ktracepoint_list.get_hash_list_begin(fnv_hash(&ip, sizeof(ip)));
    auto end = old_broken_ktracepoint_list.get_hash_list_end(fnv_hash(&ip, sizeof(ip)));

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

void tracing_buffer::write(const u8 *buf, size_t len)
{
    while (len)
    {
        // printf("wr %zu rd %zu len %zu\n", wr, rd, buflen);
        if (full())
        {
            discard_next_record();
            assert(!full());
        }

        const size_t wr_index = wr & mask;
        const size_t rd_index = rd & mask;
        // Write until the first obstacle
        size_t may_write = rd_index > wr_index ? rd_index - wr_index : buflen - wr_index;
        size_t copy_first = cul::min(may_write, len);
        // printf("May write %lu bytes until falling off, copying %lu\n", may_write,
        // copy_first);
        memcpy(buf_ + wr_index, buf, copy_first);
        len -= copy_first;
        buf += copy_first;
        wr += copy_first;
    }
}

void tracing_buffer::discard_next_record()
{
    struct tracing_header h;
    read_no_consume((u8 *) &h, sizeof(h));
    // printf("Discarding record with %u bytes\n", h.size);
    rd += h.size;
    overruns++;
}

size_t tracing_buffer::read(u8 *buf, size_t len)
{
    struct tracing_header h;
    read_no_consume((u8 *) &h, sizeof(h));
    if (h.size > len)
        return 0;

    read_no_consume(buf, cul::min((size_t) h.size, len));
    rd += h.size;
    return cul::min((size_t) h.size, len);
}

struct trace_state
{
    u32 flags;
    tracing_buffer buffer;

    trace_state(u32 flags, u32 buflen) : flags{flags}, buffer{buflen}
    {
    }
};

struct spinlock tracing_enable_lock;
PER_CPU_VAR(static struct trace_state *tstate);

#define KTRACE_ENABLE_SUPPORTED_FLAGS (TRACE_EVENT_TIME)

void ktrace_enable_on_every_cpu(const ktrace_enable &en)
{
    unsigned int ncpus = get_nr_cpus();
    for (unsigned int cpu = 0; cpu < ncpus; cpu++)
    {
        auto new_tstate = new trace_state{en.flags, en.buffer_size};
        if (!new_tstate)
            panic("out of memory allocating trace state"); /// XXX(heat): ENOMEM

        smp::sync_call(
            [](void *context) {
                trace_state *st = (trace_state *) context;
                write_per_cpu(tstate, st);
            },
            new_tstate, cpumask::one(cpu));
    }
}

mutex global_tracing_lock;
int __tracing_enabled_counter;

int ktrace_do_enable(struct ktrace_enable *uen)
{
    struct ktrace_enable en;

    if (copy_from_user(&en, uen, sizeof(en)) < 0)
        return -EFAULT;

    scoped_mutex g{global_tracing_lock};

    if (en.status != KTRACE_ENABLE_STATUS_ENABLED && en.status != KTRACE_ENABLE_STATUS_DISABLED)
        return -EINVAL;
    // TOOO: Implement DISABLED
    if (en.status == KTRACE_ENABLE_STATUS_DISABLED)
        return -EIO;

    if (en.flags & ~KTRACE_ENABLE_SUPPORTED_FLAGS)
        return -EINVAL;

    // Check if buffer size is a valid power of 2 (and > 0)
    if (count_bits(en.buffer_size) != 1)
        return -EINVAL;

    trace_event *ev = ktrace::find_event(en.evid);
    if (!ev)
        return -ENOENT;

    // Before setting the enabled flag, enable all static keys
    // so events all come out at the same time
    static_branch_enable(ev->key);

    ev->flags |= TRACE_EVENT_ENABLED;
    ev->flags |= en.flags;

    if (__tracing_enabled_counter++ == 0)
        ktrace_enable_on_every_cpu(en);

    return 0;
}

void __trace_write(u8 *buf, size_t len)
{
    auto flags = irq_save_and_disable();
    struct trace_state *st = get_per_cpu(tstate);
    if (st) [[likely]]
        st->buffer.write(buf, len);
    irq_restore(flags);
}

size_t ktrace_buf_read(size_t offset, size_t len, void *buffer, struct file *file)
{
    struct inode *ino = file->f_ino;
    u32 cpunr = (u32) (unsigned long) ino->i_helper;
    void *ptr = vmalloc(vm_size_to_pages(len), VM_TYPE_REGULAR, VM_READ | VM_WRITE, GFP_KERNEL);
    if (!ptr)
        return -ENOMEM;

    struct state
    {
        u8 *ptr;
        size_t len;
    };

    state s{(u8 *) ptr, len};

    smp::sync_call(
        [](void *context) {
            state *s = (state *) context;
            auto flags = irq_save_and_disable();
            struct trace_state *st = get_per_cpu(tstate);
            size_t to_read = s->len;
            if (st) [[likely]]
            {
                s->len = 0;
                while (to_read)
                {
                    if (st->buffer.empty())
                        break;
                    auto read = st->buffer.read(s->ptr, to_read);
                    s->len += read;
                    s->ptr += read;
                    if (read == 0)
                        break;
                    to_read -= read;
                }
            }
            else
                s->len = 0;
            irq_restore(flags);
        },
        &s, cpumask::one(cpunr));

    s.len = copy_to_user(buffer, ptr, s.len) < 0 ? -EFAULT : s.len;
    vfree(ptr);
    return s.len;
}

static atomic<ino_t> current_inode_number;

static const file_ops ktrace_buf_fops = {.read = ktrace_buf_read};

static int buffd_create(struct file **pfd, u32 cpu_nr)
{
    /* Create the node */
    struct inode *anon_ino = nullptr;
    struct file *rd = nullptr, *wr = nullptr;
    dentry *anon_dent;
    int ret = -ENOMEM;

    anon_ino = inode_create(false);
    if (!anon_ino)
        return -ENOMEM;

    anon_ino->i_dev = 0;
    anon_ino->i_mode = S_IFIFO;
    anon_ino->i_flags = INODE_FLAG_NO_SEEK;
    anon_ino->i_inode = current_inode_number++;
    anon_ino->i_fops = &ktrace_buf_fops;

    char name[NAME_MAX];
    sprintf(name, "<ktrace_buf:%u>", cpu_nr);

    anon_dent = dentry_create(name, anon_ino, nullptr);
    if (!anon_dent)
        goto err0;

    rd = inode_to_file(anon_ino);
    if (!rd)
        goto err2;

    wr = inode_to_file(anon_ino);
    if (!wr)
    {
        fd_put(rd);
        goto err2;
    }

    rd->f_dentry = anon_dent;
    wr->f_dentry = anon_dent;

    // Get new refs for the second fd
    dget(anon_dent);
    inode_ref(anon_ino);

    *pfd = rd;

    anon_ino->i_helper = (void *) (unsigned long) cpu_nr;
    return 0;
err2:
    dput(anon_dent);
err0:
    if (anon_ino)
        close_vfs(anon_ino);
    return ret;
}

int ktrace_get_buffd(u32 *ucpu)
{
    u32 cpu;

    if (get_user32(ucpu, &cpu) < 0)
        return -EFAULT;

    if (cpu >= get_nr_cpus())
        return -EINVAL;
    struct file *f;
    if (int st = buffd_create(&f, cpu); st < 0)
        return st;

    int fd = open_with_vnode(f, O_RDWR | O_CLOEXEC);
    fd_put(f);
    return fd;
}

int ktrace_get_evid(struct ktrace_getevid_format *ubuf)
{
    struct ktrace_getevid_format buf;

    if (copy_from_user(&buf, ubuf, sizeof(buf)) < 0)
        return -EFAULT;

    /* name must be null terminated and must have at least a single . (for the category.event naming
     * scheme)
     */
    if (!memchr(buf.name, 0, sizeof(buf.name)) || !memchr(buf.name, '.', sizeof(buf.name)))
        return -EINVAL;

    printk("Finding %s\n", buf.name);

    const trace_event *ev = ktrace::find_event_by_name(buf.name);

    if (!ev)
        return -ENOENT;

    buf.evid = ev->evid;

    return copy_to_user(ubuf, &buf, sizeof(buf));
}

int ktrace_get_format(struct ktrace_event_format *ubuf)
{
    int st = 0;
    ktrace_event_format format;
    if (copy_from_user(&format, ubuf, sizeof(format)) < 0)
        return -EFAULT;

    const trace_event *ev = ktrace::find_event(format.evid);
    if (!ev)
        return -ENOENT;

    size_t format_size = strlen(ev->format) + 1;

    format.format_size = format_size;

    if (format.format_size >= format_size)
    {
        if (copy_to_user(&ubuf->format, ev->format, format_size) < 0)
            return -EFAULT;
    }
    else
        st = -E2BIG;

    return copy_to_user(ubuf, &format, sizeof(format)) ?: st;
}

unsigned int ktrace_ioctl(int req, void *argp, struct file *f)
{
    if (!is_root_user())
        return -EPERM;

    switch (req)
    {
        case KTRACEENABLE: {
            return ktrace_do_enable((struct ktrace_enable *) argp);
        }

        case KTRACEGETBUFFD: {
            return ktrace_get_buffd((u32 *) argp);
        }

        case KTRACEGETEVID: {
            return ktrace_get_evid((struct ktrace_getevid_format *) argp);
        }

        case KTRACEGETFORMAT: {
            return ktrace_get_format((struct ktrace_event_format *) argp);
        }
    }
    return -ENOTTY;
}

static const file_ops ktrace_fops = {.ioctl = ktrace_ioctl};

/**
 * @brief Initialize ktrace
 *
 */
void ktrace_init()
{
    ktrace::assign_unique_evid();
    auto ex = dev_register_chardevs(0, 1, 0, &ktrace_fops, "ktrace");

    ex.unwrap()->show(0644);
}

INIT_LEVEL_CORE_KERNEL_ENTRY(ktrace_init);
