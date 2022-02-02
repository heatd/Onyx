/*
 * Copyright (c) 2020 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <onyx/dev.h>
#include <onyx/framebuffer.h>
#include <onyx/init.h>
#include <onyx/limits.h>
#include <onyx/log.h>
#include <onyx/module.h>
#include <onyx/photon-cookies.h>
#include <onyx/photon.h>
#include <onyx/process.h>
#include <onyx/scoped_lock.h>
#include <onyx/vfs.h>
#include <onyx/vm.h>

#include <pci/pci.h>

#define MPRINTF(...) printf("photon: " __VA_ARGS__)

namespace photon
{

shared_ptr<context> device::get_context(pid_t pid)
{
    scoped_lock g{context_lock};

    auto it = context_list.find(pid);

    if (it == context_list.end())
        return nullptr;

    return *it;
}

int device::create_new_context(pid_t pid)
{
    auto ctx = make_shared<context>(pid);
    if (!ctx)
        return -ENOMEM;

    scoped_lock g{context_lock};
    if (!context_list.insert({pid, ctx}))
        return -ENOMEM;

    return 0;
}

photon_handle context::add_object(const shared_ptr<object> &obj)
{
    scoped_lock g{handle_table_lock};

    return handle_table.push_back(obj) ? handle_table.size() - 1 : PHOTON_INVALID_HANDLE;
}

shared_ptr<object> context::get_object(photon_handle handle)
{
    scoped_lock g{handle_table_lock};

    if (handle >= handle_table.buf_size())
        return nullptr;

    /* If the handle is under buf_size but was deleted, it's nullptr anyway, so it all works out. */
    return handle_table[handle];
}

unsigned int context::close_object(photon_handle handle)
{
    scoped_lock g{handle_table_lock};

    if (handle >= handle_table.buf_size())
        return (unsigned int)-EINVAL;

    /* If the handle is under buf_size but was deleted, it's nullptr anyway, so it all works out. */
    auto &ptr = handle_table[handle];

    if (!ptr)
        return -EINVAL;

    ptr.reset();

    return 0;
}

shared_ptr<context> device::get_default_context()
{
    return get_context(get_current_process()->get_pid());
}

photon_handle device::add_object(const shared_ptr<object> &object, shared_ptr<context> ctx)
{
    if (!ctx)
    {
        /* We'll need to find the default context */
        /* Sadly we can't call member functions from default initialisers, which
         * would be much, much cleaner.
         */
        ctx = get_default_context();
    }

    assert(ctx != nullptr);

    return ctx->add_object(object);
}

shared_ptr<object> device::get_object(photon_handle handle, shared_ptr<context> ctx)
{
    if (!ctx)
    {
        /* We'll need to find the default context */
        /* Sadly we can't call member functions from default initialisers, which
         * would be much, much cleaner.
         */
        ctx = get_default_context();
    }

    assert(ctx != nullptr);

    return ctx->get_object(handle);
}

unsigned int device::close_object(photon_handle handle, shared_ptr<context> ctx)
{
    if (!ctx)
    {
        /* We'll need to find the default context */
        /* Sadly we can't call member functions from default initialisers, which
         * would be much, much cleaner.
         */
        ctx = get_default_context();
    }

    assert(ctx != nullptr);

    return ctx->close_object(handle);
}

void device::remove_object_from_named_list(object *obj)
{
    scoped_lock g{named_list_lock};

    list_remove(&obj->named_list);
}

void object::remove_from_named_list()
{
    dev->remove_object_from_named_list(this);

    flags &= ~PHOTON_OBJECT_NAMED;
    security_cookie = UINT64_MAX;
}

int device::do_create_dumb_buffer(photon_dumb_buffer_info &buffer)
{
    auto st = dumb_create(buffer);
    if (!st)
        return st.error();

    auto buf = st.value();

    photon_handle handle = add_object(cast<object, dumb_buffer>(buf));
    if (handle == PHOTON_INVALID_HANDLE)
        return -ENOMEM;

    // printk("Created photon buffer handle %lu %p\n", handle, buf);

    buffer.handle = handle;

    return 0;
}

int device::on_open()
{
    /* On open(), create a new process context
     * if it doesn't exist already
     */
    pid_t pid = get_current_process()->get_pid();

    if (get_context(pid))
        return 0;

    return create_new_context(pid);
}

int photon_on_open(struct file *f)
{
    auto dev = photon_dev_from_file(f);
    return dev->on_open();
}

int device::do_swap_buffers(const photon_swap_buffer_args &args)
{
    auto obj = get_object(args.buffer_handle);

    if (!obj)
        return -EINVAL;

    int ret = swap_buffers(obj.get_data());

    return ret;
}

expected<off_t, int> context::create_buffer_mapping(const shared_ptr<object> &obj, device *dev)
{
    auto map = make_shared<mapping>(dev, obj);
    if (!map)
        return {{-ENOMEM}};

    map->set_fake_off(allocate_fake_offset());

    if (!add_mapping(map))
        return {{-ENOMEM}};

    return map->fake_off();
}

off_t device::do_enable_buffer_mappings(photon_handle handle)
{
    auto context = get_default_context();

    auto obj = get_object(handle, context);

    if (!obj || !obj->is_buffer())
        return -EINVAL;

    return context->create_buffer_mapping(obj, this);
}

shared_ptr<mapping> context::get_mapping(off_t offset)
{
    scoped_lock g{mappings_lock};
    auto end = mapping_list.end();

    for (auto it = mapping_list.begin(); it != end; ++it)
    {
        auto map = *it;
        if (map->fake_off() == offset)
        {
            mapping_list.remove(map, it);
            return map;
        }
    }

    return nullptr;
}

expected<uint32_t, bool> device::generate_name()
{
    /* TODO: Eventually we'll hit the max of names even if they're all closed.
     * What should we do?
     */
    uint32_t next_name;
    uint32_t expected;

    do
    {
        expected = current_name;
        next_name = expected + 1;
        /* If we overflowed, we ran out of names, so just return an error */
        if (next_name == 0)
            return {{false}};

    } while (!current_name.compare_exchange_weak(expected, next_name));

    return expected;
}

unsigned int device::do_ioctl_set_name(photon_set_name_args *uargs)
{
    photon_set_name_args kargs;
    if (copy_from_user(&kargs, uargs, sizeof(kargs)) < 0)
        return -EFAULT;

    auto obj = get_object(kargs.handle);
    if (!obj)
        return -EINVAL;

    uint32_t name;
    auto e = generate_name();

    if (!e)
    {
        return -ERANGE;
    }

    name = e.value();

    obj->flags |= PHOTON_OBJECT_NAMED;
    obj->security_cookie = kargs.security_cookie;
    obj->name = name;

    kargs.name = name;
    if (copy_to_user(uargs, &kargs, sizeof(kargs)) < 0)
    {
        obj->flags &= ~PHOTON_OBJECT_NAMED;
        obj->security_cookie = UINT64_MAX;
        obj->name = 0;
        return -EFAULT;
    }

    scoped_lock g{named_list_lock};

    list_add(&obj->named_list, &named_list);

    return 0;
}

expected<cul::pair<object *, scoped_lock<spinlock>>, bool> device::get_object_from_name(
    uint32_t name)
{
    scoped_lock g{named_list_lock};

    list_for_every (&named_list)
    {
        object *obj = list_head_cpp<object>::self_from_list_head(l);
        if (obj->name == name)
        {
            return {{obj, cul::move(g)}};
        }
    }

    return {{false}};
}

unsigned int device::do_ioctl_open_from_name(photon_open_from_name_args *uargs)
{
    photon_open_from_name_args kargs;
    if (copy_from_user(&kargs, uargs, sizeof(kargs)) < 0)
        return -EFAULT;

    auto e = get_object_from_name(kargs.name);
    if (!e)
        return -EINVAL;

    auto obj = e.value().first;
    auto guard_lock = cul::move(e.value().second);

    if (obj->security_cookie != kargs.security_cookie)
        return -EINVAL;

    photon_handle h = add_object(shared_ptr{obj});

    if (h == PHOTON_INVALID_HANDLE)
        return -ENOMEM;

    kargs.handle = h;

    if (copy_to_user(uargs, &kargs, sizeof(kargs)) < 0)
        return -EFAULT;

    return 0;
}

unsigned int device::do_ioctl_close_handle(photon_close_handle_args *uargs)
{
    photon_close_handle_args kargs;
    if (copy_from_user(&kargs, uargs, sizeof(kargs)) < 0)
        return -EFAULT;

    return close_object(kargs.handle);
}

unsigned int device::do_ioctl_get_info(photon_info *uinfo)
{
    photon_info kinfo = {};
    strlcpy(kinfo.driver_name, driver_name, __PHOTON_INFO_MAX);
    strlcpy(kinfo.driver_version, driver_version, __PHOTON_INFO_MAX);
    strlcpy(kinfo.photon_version, photon_version_string, __PHOTON_INFO_MAX);

    return copy_to_user(uinfo, &kinfo, sizeof(kinfo));
}

unsigned int device::do_ioctl_get_bus_info_pci(photon_bus_info &info)
{
    pci::pci_device *pdev = reinterpret_cast<pci::pci_device *>(underlying_dev);

    auto &pci_info = info.info.pci_info;
    auto addr = pdev->addr();

    pci_info.addr.bus = addr.bus;
    pci_info.addr.device = addr.device;
    pci_info.addr.segment = addr.segment;
    pci_info.addr.function = addr.function;
    pci_info.device_id = pdev->did();
    pci_info.vendor_id = pdev->vid();
    pci_info.subsystem_id = pdev->get_subsystem_id();

    return 0;
}

unsigned int device::do_ioctl_get_bus_info(photon_bus_info *uinfo)
{
    unsigned int st = 0;
    photon_bus_info info;
    info.type = bus_type;

    if (bus_type == PHOTON_BUS_PCI)
        st = do_ioctl_get_bus_info_pci(info);
    else
        return -EINVAL;

    if (st != 0)
        return st;

    return copy_to_user(uinfo, &info, sizeof(info));
}

unsigned int device::do_ioctls(int request, void *argp)
{
    switch (request)
    {
    case PHOTON_IOCTL_CREATE_DUMB_BUF: {
        photon_dumb_buffer_info buf;
        if (copy_from_user(&buf, argp, sizeof(buf)) < 0)
            return -EFAULT;

        int st = do_create_dumb_buffer(buf);
        if (st < 0)
            return st;

        if (copy_to_user(argp, &buf, sizeof(buf)) < 0)
        {
            close_object(buf.handle);
            return -EFAULT;
        }

        return 0;
    }

    case PHOTON_IOCTL_SWAP_BUFS: {
        photon_swap_buffer_args a;
        if (copy_from_user(&a, argp, sizeof(a)) < 0)
            return -EFAULT;

        return do_swap_buffers(a);
    }

    case PHOTON_IOCTL_CREATE_BUF_MAP: {
        photon_create_buf_map_args args;
        if (copy_from_user(&args, argp, sizeof(args)) < 0)
            return -EFAULT;

        off_t offset = 0;
        if ((offset = do_enable_buffer_mappings(args.handle)) < 0)
            return offset;

        args.offset = offset;

        if (copy_to_user(argp, &args, sizeof(args)) < 0)
            return -EFAULT;
        return 0;
    }

    case PHOTON_IOCTL_SET_NAME:
        return do_ioctl_set_name((photon_set_name_args *)argp);

    case PHOTON_IOCTL_OPEN_FROM_NAME:
        return do_ioctl_open_from_name((photon_open_from_name_args *)argp);

    case PHOTON_IOCTL_CLOSE_OBJECT:
        return do_ioctl_close_handle((photon_close_handle_args *)argp);

    case PHOTON_IOCTL_GET_INFO:
        return do_ioctl_get_info((photon_info *)argp);

    case PHOTON_IOCTL_GET_BUS_INFO:
        return do_ioctl_get_bus_info((photon_bus_info *)argp);

    case PHOTON_IOCTL_PLATFORM_MIN ... PHOTON_IOCTL_PLATFORM_MAX:
        return handle_platform_ioctls(request, argp);

    default:
        return -EINVAL;
    }
}

unsigned int photon_ioctl(int request, void *argp, struct file *file)
{
    auto dev = photon_dev_from_file(file);

    return dev->do_ioctls(request, argp);
}

void *device::do_mmap(struct vm_region *area, struct file *f)
{
    auto context = get_default_context();

    auto mapping = context->get_mapping(area->offset);
    if (!mapping)
        return nullptr;

    struct file *fd = (file *)zalloc(sizeof(*fd));

    if (!fd)
        return nullptr;

    fd->f_ino = f->f_ino;
    inode_ref(f->f_ino);
    area->offset = 0;

    auto dbuf = cast<dumb_buffer, object>(mapping->buf());
    auto buf_size = dbuf->get_size();
    auto pages = dbuf->get_pages();
    struct vm_object *vmo = vmo_create(buf_size, (void *)dbuf.get_data());

    if (!vmo)
        return nullptr;

    size_t nr_pages = vm_size_to_pages(buf_size);
    struct page *p = pages;
    size_t off = 0;
    while (nr_pages--)
    {
        if (vmo_add_page(off, p, vmo) < 0)
        {
            vmo_destroy(vmo);
            return nullptr;
        }

        p = p->next_un.next_allocation;
        off += PAGE_SIZE;
    }

    vmo_assign_mapping(vmo, area);

    vmo->ino = f->f_ino;
    vmo->flags |= VMO_FLAG_DEVICE_MAPPING;

    area->vmo = vmo;

    return (void *)area->base;
}

void *photon_mmap(struct vm_region *area, struct file *f)
{
    auto dev = photon_dev_from_file(f);
    return dev->do_mmap(area, f);
}

static atomic<unsigned int> id_num;

const file_ops photon_fileops = {
    .ioctl = photon_ioctl, .mmap = photon_mmap, .on_open = photon_on_open};

int register_device(device *device)
{
    char name[NAME_MAX] = {0};
    snprintf(name, NAME_MAX, "photon%u", id_num++);

    auto ex = dev_register_chardevs(0, 1, 0, &photon_fileops, name);
    if (ex.has_error())
        return -ENOMEM;

    auto dev = ex.value();
    dev->show(0666);

    MPRINTF("%s devid %x:%x\n", name, MAJOR(dev->dev()), MINOR(dev->dev()));

    device->set_dev(dev);
    return 0;
}

int add_device(device *device)
{
    return register_device(device);
}

void photon_init(void)
{
    MPRINTF("Initializing the photon subsystem\n");
}

INIT_LEVEL_CORE_KERNEL_ENTRY(photon_init);

} // namespace photon
