#include <onyx/device_tree.h>
#include <onyx/driver.h>

#include "uart8250.h"

int uart8250_dt_probe(device *fake_dev)
{
    printk("dt probe\n");
    auto dev = (device_tree::node *) fake_dev;

    // Find IRQ, IO resources
    auto irq_rc = dev->get_resource(DEV_RESOURCE_FLAG_IRQ);
    printk("Irq %p\n", irq_rc);
    if (!irq_rc)
        return -1;

    auto mmio_resource = dev->get_resource(DEV_RESOURCE_FLAG_MEM);
    if (!mmio_resource)
        return -1;

    printk("Irq: %lu\n", irq_rc->start());
    volatile void *r = mmiomap((void *) mmio_resource->start(), mmio_resource->size(),
                               VM_WRITE | VM_READ | VM_NOCACHE);

    unique_ptr<uart8250_port> port =
        make_unique<uart8250_port>(r, static_cast<unsigned int>(irq_rc->start()), dev);

    if (!port)
        return -1;

    if (!port->init())
        return -1;

    while (true)
    {
        __asm__("" ::: "memory");
    }

    dev->priv = port.release();

    return 0;
}

static const char *uart8250_compatible_ids[] = {"ns16550a", nullptr};

static driver uart8250_dt = {
    .name = "uart8250-dt",
    .devids = uart8250_compatible_ids,
    .probe = uart8250_dt_probe,
    .bus_type_node = &uart8250_dt,
};

int uart8250_dt_init()
{
    printk("dt init\n");
    device_tree::register_driver(&uart8250_dt);
    return 0;
}

DRIVER_INIT(uart8250_dt_init);
