/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <errno.h>
#include <onyx/video/edid.h>
#include <onyx/cpu.h>
#include <onyx/i2c.h>

#include "igpu_drv.h"
#include "intel_regs.h"

#define igpu_gpio_write(dev, x, data)		igpu_mmio_write(dev, dev->gpio_regs_off + x, data)
#define igpu_gpio_read(dev, x)			igpu_mmio_read(dev, dev->gpio_regs_off + x)

void igpu_dump_gmbus_regs(struct igpu_device *dev)
{
	printk("GMBUS0: %08x\n", igpu_gpio_read(dev, GMBUS0));
	printk("GMBUS1: %08x\n", igpu_gpio_read(dev, GMBUS1));
	printk("GMBUS2: %08x\n", igpu_gpio_read(dev, GMBUS2));
	printk("GMBUS3: %08x\n", igpu_gpio_read(dev, GMBUS3));
	printk("GMBUS4: %08x\n", igpu_gpio_read(dev, GMBUS4));
	printk("GMBUS5: %08x\n", igpu_gpio_read(dev, GMBUS5));
}


void igpu_i2c_select(struct igpu_device *dev, uint8_t pin)
{
	printk("igpu i2c: Selecting pin %u\n", pin);
	igpu_dump_gmbus_regs(dev);

	igpu_gpio_write(dev, GMBUS0, GMBUS0_RATE_SELECT_100KHZ | pin);

	igpu_dump_gmbus_regs(dev);
	printk("igpu i2c: selected!\n");
}

int igpu_i2c_hw_rdy(struct igpu_device *dev)
{
	if(igpu_gpio_read(dev, GMBUS2) & GMBUS2_NAK_INDICATOR)
		return -1;
	return igpu_wait_bit(dev, dev->gpio_regs_off + GMBUS2,
			     GMBUS2_HW_RDY,
			     50 * NS_PER_MS, false);
}

int i2c_wait_for_completion(struct igpu_device *dev)
{
	return igpu_wait_bit(dev, dev->gpio_regs_off + GMBUS2,
			     GMBUS2_HW_WAIT_PHASE, 50 * NS_PER_MS, false);
}

int igpu_i2c_read(struct igpu_device *dev, uint8_t addr, uint8_t *buf, uint8_t count)
{
	printk("Old gmbus1: %x\n", igpu_gpio_read(dev, GMBUS1));
	uint32_t gmbus1 = 0;
	gmbus1 |= GMBUS1_BUS_CYCLE_SELECT(GMBUS1_BUS_CYCLE_NO_IDX_NO_STOP_WAIT);
	gmbus1 |= GMBUS1_ASSERT_SWRDY;
	gmbus1 |= GMBUS1_TOTAL_BYTE_COUNT(count);
	gmbus1 |= GMBUS1_SLAVE_ADDR_AND_DIR(1 | (addr << 1));
	printk("Addr: %x\n", addr);


	igpu_gpio_write(dev, GMBUS1, gmbus1);
	igpu_gpio_write(dev, GMBUS5, 0);
	printk("Dev gpio regs off: %x\n", dev->gpio_regs_off + GMBUS1);

	igpu_dump_gmbus_regs(dev);
	while(count != 0)
	{
		if(igpu_i2c_hw_rdy(dev) < 0)
		{
			printk("i2c read timed out\n");
			return -ENXIO;
		}

		printk("Reading.\n");

		uint32_t *ptr = (uint32_t *) buf;

		*ptr = igpu_gpio_read(dev, GMBUS3);
		buf += 4;
		count -= 4;
	}

	return i2c_wait_for_completion(dev);
}

int igpu_i2c_write(struct igpu_device *dev, uint8_t addr, uint8_t *buf, uint8_t count)
{
	uint32_t gmbus1 = 0;
	gmbus1 |= GMBUS1_BUS_CYCLE_SELECT(GMBUS1_BUS_CYCLE_NO_IDX_STOP);
	gmbus1 |= GMBUS1_ASSERT_SWRDY;
	gmbus1 |= GMBUS1_TOTAL_BYTE_COUNT(count);
	gmbus1 |= GMBUS1_SLAVE_ADDR_AND_DIR((addr << 1));

	igpu_gpio_write(dev, GMBUS1, gmbus1);
	igpu_gpio_write(dev, GMBUS5, 0);

	igpu_dump_gmbus_regs(dev);
	while(count != 0)
	{
		igpu_gpio_write(dev, GMBUS3, *(uint32_t *) buf);

		if(igpu_i2c_hw_rdy(dev) < 0)
		{
			printk("i2c write timed out\n");
			return -ENXIO;
		}

		buf += 4;
		count -= 4;
	}

	return i2c_wait_for_completion(dev);
}

void igpu_i2c_finish_transaction(struct igpu_device *dev)
{
	uint32_t gmbus1 = 0;
	gmbus1 |= GMBUS1_BUS_CYCLE_SELECT(GMBUS1_BUS_CYCLE_NO_IDX_STOP);
	gmbus1 |= GMBUS1_ASSERT_SWRDY;
	igpu_gpio_write(dev, GMBUS1, gmbus1);

	int st = igpu_wait_bit(dev, dev->gpio_regs_off + GMBUS2,
			       GMBUS2_GMBUS_ACTIVE, 100 * NS_PER_MS, true);

	uint32_t gmbus0 = 0;
	igpu_gpio_write(dev, GMBUS0, gmbus0);

	if(st == ETIMEDOUT)
	{
		printk("IGPU error: Failed to go idle\n");
	}

	igpu_gpio_write(dev, GMBUS1, GMBUS1_SW_CLR_INT);
	igpu_gpio_write(dev, GMBUS1, 0);
}

int igpu_i2c_do_message(struct igpu_device *dev, struct i2c_message *msg)
{
	int st = 0;
	if(!msg->write)
	{
		st = igpu_i2c_read(dev, (uint8_t) msg->addr, msg->buffer,
				   (uint8_t) msg->length);
	}
	else
	{
		st = igpu_i2c_write(dev, (uint8_t) msg->addr, msg->buffer,
				    (uint8_t) msg->length);
	}

	igpu_i2c_finish_transaction(dev);

	if(st < 0)
		return st;
	
	msg->transfered = msg->length;

	return 0;
}

int igpu_transaction(struct i2c_adapter *adapter, struct i2c_message *msgs,
		     size_t nr)
{
	struct igpu_device *dev = adapter->priv;

	for(size_t i = 0; i < nr; i++)
	{
		int st = igpu_i2c_do_message(dev, &msgs[i]);
		if(st < 0)
			return st;
	}

	return 0;
}

int igpu_i2c_init(struct igpu_device *dev)
{
	if(!HAS_GMCH_DISPLAY(dev))
	{
		/* Set the PCH offset */
		dev->gpio_regs_off = GPIO_PCH_BASE;
	}

	dev->i2c_adapter.priv = dev;
	memset(&dev->i2c_adapter.mtx, 0, sizeof(struct mutex));
	dev->i2c_adapter.name = "igpu-i2c";
	dev->i2c_adapter.do_batch_transfer = igpu_transaction;

	return 0;
	
}