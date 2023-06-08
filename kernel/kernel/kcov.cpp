/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <onyx/dev.h>
#include <onyx/init.h>
#include <onyx/irq.h>
#include <onyx/kcov.h>
#include <onyx/kunit.h>
#include <onyx/softirq.h>
#include <onyx/thread.h>
#include <onyx/types.h>
#include <onyx/vfs.h>

#include <uapi/kcov.h>

enum kcov_state
{
    /* KCOV device was opened */
    KCOV_STATE_OPEN,
    /* Buffer has been allocated (through KCOV_INIT_TRACE) */
    KCOV_STATE_READY,
    /* KCOV has been enabled for a thread. Sancov is now in operation */
    KCOV_STATE_RUNNING,
    /* fd was closed */
    KCOV_STATE_DYING
};

struct kcov_data
{
    spinlock lock;
    enum kcov_state state;
    enum kcov_tracing_mode tracing_mode;
    unsigned long *buffer;
    vm_object *vmo;
    unsigned long nr_elements;
    struct thread *owner;
};

static bool may_trace_cov(enum kcov_tracing_mode desired, struct thread *thread)
{
    if (!thread) [[unlikely]]
        return false;
    // Exclude hard irq code, softirq from any sort of tracing, in order to reduce noise
    if (is_in_interrupt() || softirq_is_handling()) [[unlikely]]
        return false;
    const auto data = thread->kcov_data;
    return data != nullptr && data->tracing_mode == KCOV_TRACING_TRACE_PC;
}

extern "C" void __sanitizer_cov_trace_pc()
{
    unsigned long pc = (unsigned long) __builtin_return_address(0);
    auto current = get_current_thread();

    if (!may_trace_cov(KCOV_TRACING_TRACE_PC, current)) [[unlikely]]
        return;

    struct kcov_data *data = current->kcov_data;

    const auto nr_elems = __atomic_load_n(data->buffer, __ATOMIC_RELAXED);

    if (nr_elems + 1 < data->nr_elements) [[likely]]
    {
        __atomic_store_n(&data->buffer[nr_elems + 1], pc, __ATOMIC_RELAXED);
        __atomic_store_n(data->buffer, nr_elems + 1, __ATOMIC_RELAXED);
    }
}

static int __kcov_disable(struct kcov_data *data)
{
    if (data->state != KCOV_STATE_RUNNING)
        return -EBUSY;

    auto current = get_current_thread();

    if (current->kcov_data != data)
        return -EINVAL;

    __atomic_store_n(&current->kcov_data, nullptr, __ATOMIC_RELAXED);
    __atomic_store_n(&data->state, KCOV_STATE_READY, __ATOMIC_RELEASE);
    __atomic_store_n(&data->tracing_mode, KCOV_TRACING_NONE, __ATOMIC_RELAXED);
    __atomic_store_n(&data->owner, nullptr, __ATOMIC_RELAXED);

    // atomic_thread_fence(mem_order::acq_rel);

    return 0;
}

static int kcov_disable(struct kcov_data *data)
{
    scoped_lock g{data->lock};
    return __kcov_disable(data);
}

// Our VMO ops are a noop, since we have filled the VMO out with the correct size and pages
const static struct vm_object_ops kcov_vmo_ops = {};

static int kcov_setup_vmo(struct vm_object *vmo, void *buffer)
{
    // vmalloc_to_pages gives us refs, we give them away to the vm_object (through vmo_add_page)
    auto pages = vmalloc_to_pages(buffer);
    size_t off = 0;

    for (struct page *p = pages; p; p = p->next_un.next_allocation, off += PAGE_SIZE)
    {
        if (vmo_add_page(off, p, vmo) < 0)
            return -ENOMEM;
    }

    vmo->ops = &kcov_vmo_ops;

    return 0;
}

int kcov_init_trace(unsigned long nr_elems, struct file *f)
{
    int st;
    struct kcov_data *data = (struct kcov_data *) f->private_data;
    vm_object *vmo = nullptr;

    // Too small, needs to hold at least one PC and the position
    if (nr_elems < 2)
        return -EINVAL;

    size_t size = nr_elems * sizeof(unsigned long);

    // Lets limit the buffer to a reasonable size
    if (size > INT_MAX)
        return -EINVAL;

    // We use a vmalloc region and set up a VMO for it. This VMO is then mmap'd.
    auto buffer = (unsigned long *) vmalloc(vm_size_to_pages(size), VM_TYPE_REGULAR,
                                            VM_READ | VM_WRITE, GFP_KERNEL);

    if (!buffer)
        return -ENOMEM;

    vmo = vmo_create(size, nullptr);
    if (!vmo)
    {
        st = -ENOMEM;
        goto err;
    }

    if (st = kcov_setup_vmo(vmo, buffer); st < 0)
    {
        goto err;
    }

    // We grab this lock later because kcov_setup_vmo must touch sleepable locks in VMO code
    spin_lock(&data->lock);

    if (data->state != KCOV_STATE_OPEN)
    {
        spin_unlock(&data->lock);
        st = -EBUSY;
        goto err;
    }

    data->nr_elements = nr_elems - 1;
    data->buffer = buffer;
    data->vmo = vmo;
    data->state = KCOV_STATE_READY;

    spin_unlock(&data->lock);

    return 0;
err:
    if (buffer)
        vfree(buffer, vm_size_to_pages(size));
    if (vmo)
        vmo_destroy(vmo);
    return st;
}

static int kcov_enable(unsigned int mode, struct file *f)
{
    struct kcov_data *data = (struct kcov_data *) f->private_data;
    scoped_lock g{data->lock};
    auto current = get_current_thread();

    if (mode >= KCOV_TRACING_MAX)
        return -EINVAL;

    // We must only possibly enable if we have a buffer already
    if (data->state != KCOV_STATE_READY)
        return -EBUSY;

    // We must not have it enabled already
    if (current->kcov_data)
        return -EINVAL;

    current->kcov_data = data;
    data->tracing_mode = (kcov_tracing_mode) mode;
    data->owner = current;

    // READY -> RUNNING. Must have a release semantic here
    __atomic_store_n(&data->state, KCOV_STATE_RUNNING, __ATOMIC_RELEASE);

    return 0;
}

unsigned int kcov_ioctl(int req, void *argp, struct file *f)
{
    switch (req)
    {
        case KCOV_INIT_TRACE:
            return kcov_init_trace((unsigned long) argp, f);
        case KCOV_ENABLE:
            return kcov_enable((unsigned int) (unsigned long) argp, f);
        case KCOV_DISABLE:
            return kcov_disable((struct kcov_data *) f->private_data);
    }

    return -ENOTTY;
}

int kcov_open(struct file *file)
{
    // Allocate a new kcov_data structure that will serve us well while this file is alive
    // This solves any problems with mmap lifetime or whatnot, since those hold struct file refs
    auto data = make_unique<kcov_data>();
    if (!data)
        return -ENOMEM;
    spinlock_init(&data->lock);
    data->state = KCOV_STATE_OPEN;
    data->buffer = nullptr;
    data->nr_elements = 0;
    data->tracing_mode = KCOV_TRACING_NONE;
    data->owner = nullptr;

    file->private_data = data.release();
    return 0;
}

void kcov_free(struct kcov_data *data)
{
    if (data->buffer)
        vfree(data->buffer, vm_size_to_pages((data->nr_elements + 1) * sizeof(unsigned long)));
    if (data->vmo)
        vmo_unref(data->vmo);

    delete data;
}

void kcov_close(struct file *f)
{
    auto data = (struct kcov_data *) f->private_data;
    DCHECK(data != nullptr);

    if (data->state != KCOV_STATE_RUNNING)
    {
        kcov_free(data);
        f->private_data = nullptr;
    }
    else
    {
        scoped_lock g{data->lock};
        // Set it to dying. The thread it's attached to will free it when it exits
        data->state = KCOV_STATE_DYING;
    }
}

void kcov_free_thread(struct thread *thread)
{
    auto data = thread->kcov_data;

    if (data)
    {
        scoped_lock g{data->lock};

        if (data->state != KCOV_STATE_DYING)
        {
            int st = __kcov_disable(data);
            DCHECK(st == 0);
        }
        else
        {
            g.unlock();
            // De-attach ourselves before freeing
            __atomic_store_n(&thread->kcov_data, nullptr, __ATOMIC_RELAXED);
            kcov_free(data);
        }
    }
}

void *kcov_mmap(struct vm_region *area, struct file *node)
{
    if (area->offset != 0)
        return errno = EINVAL, nullptr;
    if (area->mapping_type != MAP_SHARED)
        return errno = EINVAL, nullptr;

    auto data = (struct kcov_data *) node->private_data;

    scoped_lock g{data->lock};

    if (data->state == KCOV_STATE_OPEN)
    {
        // If we have not initialized the buffer yet, EINVAL
        return errno = EINVAL, nullptr;
    }

    area->vmo = data->vmo;
    vmo_ref(area->vmo);

    g.unlock();

    vmo_assign_mapping(area->vmo, area);

    return (void *) area->base;
}

static const file_ops kcov_fops = {
    .ioctl = kcov_ioctl, .mmap = kcov_mmap, .on_open = kcov_open, .release = kcov_close};

/**
 * @brief Initialize kcov
 *
 */
void kcov_init()
{
    auto ex = dev_register_chardevs(0, 1, 0, &kcov_fops, "kcov");

    ex.unwrap()->show(0600);
}

INIT_LEVEL_CORE_KERNEL_ENTRY(kcov_init);

#ifdef CONFIG_KUNIT

// TODO(heat): our unique_ptr lacks a deleter feature so we leak memory on every kcov test
static unique_ptr<file> create_mock_file()
{
    auto filp = make_unique<file>();
    if (!filp)
        return nullptr;

    if (kcov_open(filp.get()) < 0)
        return nullptr;
    return filp;
}

static kcov_data *kcov_data_from_file(file *filp)
{
    return (kcov_data *) filp->private_data;
}

TEST(kcov, initial_state)
{
    auto file = create_mock_file();
    ASSERT_NONNULL(file.get());

    auto data = kcov_data_from_file(file.get());

    EXPECT_EQ(data->state, KCOV_STATE_OPEN);
    EXPECT_NULL(data->buffer);
    EXPECT_NULL(data->vmo);
    EXPECT_EQ(data->nr_elements, 0U);
    EXPECT_EQ(data->tracing_mode, KCOV_TRACING_NONE);
}

TEST(kcov, init_trace_works)
{
    auto file = create_mock_file();
    ASSERT_NONNULL(file.get());

    constexpr size_t size = 10;

    int st = kcov_ioctl(KCOV_INIT_TRACE, (void *) size, file.get());
    ASSERT_EQ(st, 0);

    auto data = kcov_data_from_file(file.get());

    EXPECT_EQ(data->state, KCOV_STATE_READY);
    EXPECT_EQ(data->nr_elements, size - 1);
    EXPECT_NONNULL(data->buffer);
    ASSERT_NONNULL(data->vmo);
    EXPECT_EQ(data->vmo->size, vm_size_to_pages(size * sizeof(unsigned long)) << PAGE_SHIFT);
}

TEST(kcov, bad_init_trace_requests)
{
    auto file = create_mock_file();
    ASSERT_NONNULL(file.get());

    // Try bad sizes
    int st = kcov_ioctl(KCOV_INIT_TRACE, (void *) 0UL, file.get());
    EXPECT_EQ(st, -EINVAL);

    st = kcov_ioctl(KCOV_INIT_TRACE, (void *) 1UL, file.get());
    EXPECT_EQ(st, -EINVAL);

    st = kcov_ioctl(KCOV_INIT_TRACE, (void *) ((INT_MAX / sizeof(unsigned long)) + 1), file.get());
    EXPECT_EQ(st, -EINVAL);

    auto data = kcov_data_from_file(file.get());

    ASSERT_NULL(data->vmo);
    ASSERT_EQ(data->state, KCOV_STATE_OPEN);

    // Now do a proper init, and then try to redo it
    constexpr size_t size = 10;

    st = kcov_ioctl(KCOV_INIT_TRACE, (void *) size, file.get());
    ASSERT_EQ(st, 0);

    st = kcov_ioctl(KCOV_INIT_TRACE, (void *) size, file.get());
    ASSERT_EQ(st, -EBUSY);

    EXPECT_EQ(data->state, KCOV_STATE_READY);
    ASSERT_NONNULL(data->vmo);
}

TEST(kcov, enable_disable_works)
{
    auto file = create_mock_file();
    ASSERT_NONNULL(file.get());

    auto data = kcov_data_from_file(file.get());

    // Init the trace buffer
    int st = kcov_ioctl(KCOV_INIT_TRACE, (void *) 4UL, file.get());
    EXPECT_EQ(st, 0);
    ASSERT_EQ(data->state, KCOV_STATE_READY);

    st = kcov_enable(KCOV_TRACING_TRACE_PC, file.get());

    ASSERT_EQ(st, 0);
    EXPECT_EQ(data->state, KCOV_STATE_RUNNING);
    EXPECT_EQ(get_current_thread()->kcov_data, data);
    EXPECT_EQ(data->owner, get_current_thread());
    EXPECT_EQ(data->tracing_mode, KCOV_TRACING_TRACE_PC);

    // Attempt to trace something
    data->buffer[0] = 0;
    __sanitizer_cov_trace_pc();

    EXPECT_EQ(data->buffer[0], 1UL);
    EXPECT_NE(data->buffer[1], 0UL);

    // Now disable it and check for state and __sanitizer_cov_trace_pc() behavior
    st = kcov_disable(data);
    ASSERT_EQ(st, 0);

    EXPECT_EQ(data->state, KCOV_STATE_READY);
    EXPECT_NULL(get_current_thread()->kcov_data);
    EXPECT_NULL(data->owner);
    EXPECT_EQ(data->tracing_mode, KCOV_TRACING_NONE);

    const auto i = data->buffer[0];
    __sanitizer_cov_trace_pc();
    EXPECT_EQ(i, data->buffer[0]);
}

TEST(kcov, close_test)
{
    auto file = create_mock_file();
    ASSERT_NONNULL(file.get());

    auto data = kcov_data_from_file(file.get());

    // Init the trace buffer
    int st = kcov_ioctl(KCOV_INIT_TRACE, (void *) 4UL, file.get());
    EXPECT_EQ(st, 0);
    ASSERT_EQ(data->state, KCOV_STATE_READY);

    kcov_close(file.get());
    EXPECT_NULL(file->private_data);
}

TEST(kcov, close_while_running_test)
{
    auto file = create_mock_file();
    ASSERT_NONNULL(file.get());

    auto data = kcov_data_from_file(file.get());

    // Init the trace buffer
    int st = kcov_ioctl(KCOV_INIT_TRACE, (void *) 4UL, file.get());
    EXPECT_EQ(st, 0);
    ASSERT_EQ(data->state, KCOV_STATE_READY);

    // READY -> RUNNING
    st = kcov_enable(KCOV_TRACING_TRACE_PC, file.get());

    ASSERT_EQ(st, 0);
    ASSERT_EQ(data->state, KCOV_STATE_RUNNING);

    // RUNNING -> DYING
    kcov_close(file.get());
    EXPECT_NONNULL(file->private_data);
    EXPECT_EQ(data->state, KCOV_STATE_DYING);
    EXPECT_NONNULL(data->buffer);
    EXPECT_NONNULL(data->vmo);

    // Finish dying
    kcov_free_thread(get_current_thread());
    ASSERT_NULL(get_current_thread()->kcov_data);
}

TEST(kcov, thread_exit_while_tracing)
{
    auto file = create_mock_file();
    ASSERT_NONNULL(file.get());

    auto data = kcov_data_from_file(file.get());

    // Init the trace buffer
    int st = kcov_ioctl(KCOV_INIT_TRACE, (void *) 4UL, file.get());
    EXPECT_EQ(st, 0);
    ASSERT_EQ(data->state, KCOV_STATE_READY);

    // READY -> RUNNING
    st = kcov_enable(KCOV_TRACING_TRACE_PC, file.get());

    ASSERT_EQ(st, 0);
    ASSERT_EQ(data->state, KCOV_STATE_RUNNING);

    // Now die
    kcov_free_thread(get_current_thread());
    ASSERT_NULL(get_current_thread()->kcov_data);

    EXPECT_EQ(data->state, KCOV_STATE_READY);
    EXPECT_EQ(data->tracing_mode, KCOV_TRACING_NONE);
    EXPECT_NONNULL(data->buffer);
    EXPECT_NONNULL(data->vmo);
    EXPECT_NULL(data->owner);
}

#endif
