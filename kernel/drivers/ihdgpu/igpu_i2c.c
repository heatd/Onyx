/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <errno.h>
#include <onyx/video/edid.h>
#include <onyx/cpu.h>

#include "igpu_drv.h"
#include "intel_regs.h"

#define igpu_gpio_write(dev, x, data)		igpu_mmio_write(dev, dev->gpio_regs_off + x, data)
#define igpu_gpio_read(dev, x)			igpu_mmio_read(dev, dev->gpio_regs_off + x)

void igpu_i2c_select(struct igpu_device *dev, uint8_t pin)
{
	printk("igpu i2c: Selecting pin %u\n", pin);

	igpu_gpio_write(dev, GMBUS0, GMBUS0_RATE_SELECT_100KHZ | pin);
}

int igpu_i2c_read(struct igpu_device *dev, uint8_t *buf, uint8_t count)
{
	uint32_t gmbus1 = 0;
	gmbus1 |= GMBUS1_BUS_CYCLE_NO_IDX_NO_STOP_WAIT;
	gmbus1 |= GMBUS1_ASSERT_SWRDY;
	gmbus1 |= GMBUS1_TOTAL_BYTE_COUNT(count);
	gmbus1 |= GMBUS1_SLAVE_ADDR_AND_DIR(1 | (0x50 << 1));
	igpu_gpio_write(dev, GMBUS1, gmbus1);

	if(igpu_gpio_read(dev, GMBUS2) & GMBUS2_NAK_INDICATOR)
		return -ENXIO;
	while(count != 0)
	{
		while(!(igpu_gpio_read(dev, GMBUS2) & GMBUS2_HW_RDY))
			cpu_relax();
		uint32_t *ptr = (uint32_t *) buf;

		*ptr = igpu_gpio_read(dev, GMBUS3);
		buf += 4;
		count -= 4;
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

	for(int i = 4; i <= IGPU_NR_GMBUS; ++i)
	{
		igpu_i2c_select(dev, i);
	
		struct edid_data buffer;
		if(igpu_i2c_read(dev, (uint8_t *) &buffer, 128) == -ENXIO)
			continue;

		printk("edid version %u\n", buffer.edid_version);
	}

	return 0;
	
}