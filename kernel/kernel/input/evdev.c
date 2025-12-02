/*
 * Copyright (c) 2025 - 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdio.h>

#include <onyx/file.h>
#include <onyx/input-event-codes.h>
#include <onyx/input/device.h>
#include <onyx/mm/slab.h>
#include <onyx/poll.h>
#include <onyx/rculist.h>

#include <asm/ioctl.h>
#include <uapi/ioctl.h>

static void evdev_append_client(struct input_device *dev, struct evdev_client *client)
{
    spin_lock(&dev->client_list_lock);
    list_add_tail_rcu(&client->node, &dev->client_list);
    spin_unlock(&dev->client_list_lock);
}

static void evdev_post_event(struct evdev_client *client, struct evdev_input_event *ev)
{
    unsigned long flags = spin_lock_irqsave(&client->buffer_lock);

    if (client->write - client->read == client->buf_size)
    {
        /* Full? Bump read ahead */
        client->read++;
    }

    memcpy(&client->buffer[client->write & (client->buf_size - 1)], ev,
           sizeof(struct evdev_input_event));
    client->write++;
    spin_unlock_irqrestore(&client->buffer_lock, flags);
    wait_queue_wake_all(&client->wq);
}

void evdev_submit_event(struct input_device *dev, struct evdev_input_event *ev)
{
    struct evdev_client *client;
    struct evdev_client *grab;

    rcu_read_lock();
    grab = rcu_access_pointer(dev->grab);
    list_for_each_entry_rcu (client, &dev->client_list, node)
    {
        if (grab && grab != client)
            continue;
        evdev_post_event(client, ev);
    }
    rcu_read_unlock();
}

static int evdev_open(struct file *filp)
{
    struct input_device *dev = filp->f_ino->i_helper;
    struct evdev_client *client;

    client = kmalloc(sizeof(*client), GFP_KERNEL);
    if (!client)
        return -ENOMEM;
    client->buf_size = 64;
    client->buffer = kcalloc(client->buf_size, sizeof(struct evdev_input_event), GFP_KERNEL);
    if (!client->buffer)
    {
        kfree(client);
        return -ENOMEM;
    }

    client->write = client->read = 0;
    client->dev = dev;
    spinlock_init(&client->buffer_lock);
    evdev_append_client(dev, client);
    filp->private_data = client;
    init_wait_queue_head(&client->wq);
    return 0;
}

static bool evdev_consume_event(struct evdev_client *ev, struct evdev_input_event *event)
{
    bool consumed = false;
    unsigned long flags = spin_lock_irqsave(&ev->buffer_lock);

    if (ev->read != ev->write)
    {
        memcpy(event, &ev->buffer[ev->read & (ev->buf_size - 1)], sizeof(struct evdev_input_event));
        ev->read++;
        consumed = true;
    }

    spin_unlock_irqrestore(&ev->buffer_lock, flags);
    return consumed;
}

static ssize_t evdev_read_iter(struct file *filp, size_t offset, struct iovec_iter *iter,
                               unsigned int flags)
{
    struct evdev_client *client;
    struct evdev_input_event ev;
    ssize_t err = 0, tmp;

    client = filp->private_data;
    if (iter->bytes != 0 && iter->bytes < sizeof(struct evdev_input_event))
        return -EINVAL;

    for (;;)
    {
        if (client->read == client->write && (flags & O_NONBLOCK))
            return -EAGAIN;

        while (iter->bytes >= sizeof(struct evdev_input_event) && evdev_consume_event(client, &ev))
        {
            tmp = copy_to_iter(iter, &ev, sizeof(struct evdev_input_event));
            if (tmp > 0)
                err += tmp;
            else
                err = err ?: tmp;
        }

        if (err)
            break;
        err = wait_for_event_interruptible(&client->wq, client->read != client->write);
        if (err)
            break;
    }

    return err;
}

static short evdev_poll(void *poll_file, short events, struct file *filp)
{
    struct evdev_client *client = filp->private_data;
    unsigned long flags;
    short revents = 0;

    flags = spin_lock_irqsave(&client->buffer_lock);
    if (client->read != client->write)
        revents |= POLLIN;
    else
        poll_wait_helper(poll_file, &client->wq);

    spin_unlock_irqrestore(&client->buffer_lock, flags);
    return events & revents;
}

#define EV_VERSION 0x010001

static int evdev_copy_str(const char *string, unsigned int len, void *argp)
{
    int to_copy = min(len, strlen(string) + 1);

    return copy_to_user(argp, string, to_copy) ? -EFAULT : to_copy;
}

static int evdev_copy_bits(void *user, void *buf, unsigned int iocsize, unsigned int len)
{
    if (len > iocsize)
        len = iocsize;
    return copy_to_user(user, buf, len) ? -EFAULT : (int) len;
}

static int do_eviocgbit(struct input_device *dev, unsigned int ev_type, void *buf,
                        unsigned int iocsize)
{
    unsigned long dummy = 0;
    unsigned long *bits = &dummy;
    unsigned int len = sizeof(dummy);

    switch (ev_type)
    {
        case 0:
            bits = &dev->feature_bits;
            len = sizeof(dev->feature_bits);
            break;
        case EV_KEY:
            bits = dev->key_bits;
            len = sizeof(dev->key_bits);
            break;
        case EV_REL:
        case EV_ABS:
        case EV_MSC:
        case EV_SW:
        case EV_LED:
        case EV_SND:
        case EV_REP:
        case EV_FF:
        case EV_PWR:
        case EV_FF_STATUS:
            break;
        default:
            return -EINVAL;
    }

    return evdev_copy_bits(buf, bits, iocsize, len);
}

static int evdev_grab(struct evdev_client *client, struct input_device *dev)
{
    unsigned long flags;
    int err = -EBUSY;

    flags = spin_lock_irqsave(&dev->client_list_lock);

    if (dev->grab)
        goto out;

    rcu_assign_pointer(dev->grab, client);
    err = 0;
out:
    spin_unlock_irqrestore(&dev->client_list_lock, flags);
    return err;
}

static int evdev_ungrab(struct evdev_client *client, struct input_device *dev)
{
    unsigned long flags;
    int err = -EINVAL;

    flags = spin_lock_irqsave(&dev->client_list_lock);

    if (dev->grab != client)
        goto out;

    rcu_assign_pointer(dev->grab, NULL);
    err = 0;
out:
    spin_unlock_irqrestore(&dev->client_list_lock, flags);
    return err;
}

static void evdev_drop_events(struct evdev_client *client, int type)
{
    unsigned long flags;

    flags = spin_lock_irqsave(&client->buffer_lock);

    /* TODO: Write this... */
#if 0
    for (unsigned long pos = client->read, read = client->read; pos != client->write; pos++)
    {
        if (client->buffer[pos & (client->buf_size - 1)].type != type)
            continue;

        /* front of queue? increment read */
        if (pos == client->read)
        {
            client->read++;
            continue;
        }

        /* We're not in front of the queue, thus we need to copy it back manually */

        ev->read++;
        consumed = true;
    }
#endif
    spin_unlock_irqrestore(&client->buffer_lock, flags);
}

static int do_eviocgkey(struct input_device *dev, struct evdev_client *client, unsigned int iocsize,
                        void *argp)
{
    /* Remove EV_KEY inputs from our buffer, so the client doesn't register things twice. */
    /* TODO: We should probably have a lock on this. */
    return evdev_copy_bits(argp, dev->state.keys_pressed, iocsize, sizeof(dev->state.keys_pressed));
}

static unsigned int evdev_ioctl(int request, void *argp, struct file *file)
{
    struct evdev_client *client = file->private_data;
    struct input_device *dev = client->dev;
    unsigned int iocsize;

    pr_info("evdev: ioctl %x\n", request);

    switch (request)
    {
        case EVIOCGVERSION: {
            int version = EV_VERSION;
            return copy_to_user(argp, &version, sizeof(version));
        }
        case EVIOCGID: {
            return copy_to_user(argp, &dev->input_id, sizeof(struct input_id));
        }
        case EVIOCGRAB: {
            if (argp)
                return evdev_grab(client, dev);
            else
                return evdev_ungrab(client, dev);
        }
    }

        /* yuck */
#define _IOC_RAWSIZMASK      (_IOC_SIZEMASK << 16)
#define _IOC_NOSIZE(request) ((request) & ~_IOC_RAWSIZMASK)
    iocsize = _IOC_SIZE(request);
    switch (_IOC_NOSIZE(request))
    {
        case EVIOCGNAME(0):
            return evdev_copy_str(dev->name, iocsize, argp);
        case EVIOCGPROP(0):
            return evdev_copy_bits(argp, &dev->properties, iocsize, sizeof(dev->properties));
        case EVIOCGPHYS(0):
            return evdev_copy_str(dev->phys, iocsize, argp);
        case EVIOCGUNIQ(0):
            return evdev_copy_str("", iocsize, argp);
        case EVIOCGKEY(0):
            return do_eviocgkey(dev, client, iocsize, argp);
    }

    /* yuck x2 */
    if (_IOC_TYPE(request) != 'E')
        return -EINVAL;
    if ((_IOC_NR(request) & ~EV_MAX) == _IOC_NR(EVIOCGBIT(0, 0)))
        return do_eviocgbit(dev, _IOC_NR(request) & EV_MAX, argp, iocsize);

    return -ENOTTY;
}

static void evdev_destroy(struct rcu_head *head)
{
    struct evdev_client *client = container_of(head, struct evdev_client, rcu_head);

    kfree(client->buffer);
    kfree(client);
}

static void evdev_release(struct file *filp)
{
    struct evdev_client *client = filp->private_data;
    struct input_device *dev = client->dev;
    unsigned long flags;

    flags = spin_lock_irqsave(&dev->client_list_lock);
    if (dev->grab == client)
        rcu_assign_pointer(dev->grab, NULL);
    list_remove_rcu(&client->node);
    spin_unlock_irqrestore(&dev->client_list_lock, flags);

    /* RCU-delay the destruction */
    call_rcu(&client->rcu_head, evdev_destroy);
}

const struct file_ops evdev_fops = {
    .on_open = evdev_open,
    .read_iter = evdev_read_iter,
    .poll = evdev_poll,
    .ioctl = evdev_ioctl,
    .release = evdev_release,
};
