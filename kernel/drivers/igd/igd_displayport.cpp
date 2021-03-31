/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <errno.h>
#include <stdlib.h>

#include "intel_regs.h"
#include "igpu_drv.h"

#include <onyx/i2c.h>
#include <onyx/timer.h>

int ddaux_do_transfers(struct i2c_adapter *adapter,
				     struct i2c_message *messages, size_t nr);

#define LITTLE_TO_BIG32(n) (((n) >> 24) & 0xFF) | (((n) << 8) & 0xFF0000) | \
			   (((n) >> 8) & 0xFF00) | (((n) << 24) & 0xFF000000)


#define DDI_AUX_REPLY_AUX_ACK 0
#define DDI_AUX_REPLY_AUX_NACK 1
#define DDI_AUX_REPLY_AUX_DEFER 2
#define DDI_AUX_REPLY_I2C_NACK 4
#define DDI_AUX_REPLY_I2C_DEFER 8

int ddaux_do_transfer(struct i2c_adapter *adapter,
				     struct i2c_message *message)
{
	struct igd_displayport *port = (igd_displayport *) adapter->priv;

	uint8_t data[20];
	uint8_t cmd;
	uint8_t size = 4;

	if(message->write)
		cmd = DP_AUX_I2C_WRITE;
	else
		cmd = DP_AUX_I2C_READ;

	data[0] = (uint8_t) ((cmd << 4) | ((message->addr >> 16) & 0xf));
	data[1] = (uint8_t) ((message->addr >> 8));
	data[2] = (uint8_t) ((message->addr)); 
	data[3] = (size - 1);

	if(message->write)
	{
		size += message->length;
		memcpy(data + 4, message->buffer, message->length);
	}

	for(unsigned int i = 0; i < size; i += 4)
	{
		uint32_t *ptr = (uint32_t *) (&data[i]);
		igpu_mmio_write(port->device, port->data_base_reg + i,
				LITTLE_TO_BIG32(*ptr));
	}

	uint32_t ddaux_ctl = 0;

	ddaux_ctl |= DDI_AUX_CTL_MESSAGE_SIZE((size - 1));
	ddaux_ctl |= DDI_AUX_CTL_TIMEOUT_1600US;
	ddaux_ctl |= DDI_AUX_CTL_DONE;
	ddaux_ctl |= DDI_AUX_CTL_receive_ERROR;
	ddaux_ctl |= DDI_AUX_CTL_TIMEOUT_ERROR;
	ddaux_ctl |= DDI_AUX_CTL_SEND_BUSY;
	ddaux_ctl |= DDI_AUX_CTL_IRQ_ON_DONE; /* 1 means disabled */
	ddaux_ctl |= 225;
	ddaux_ctl |= (0x3 << 16);		/* Default precharge time and bit clock divider */

	printk("Writing ddaux %x\n", ddaux_ctl);

	igpu_mmio_write(port->device, port->ctl_reg, ddaux_ctl);

	for(int i = 0; i < 10000; i++)
	{
		ddaux_ctl = igpu_mmio_read(port->device, port->ctl_reg);

		if(!(ddaux_ctl & DDI_AUX_CTL_SEND_BUSY))
		{
			if(ddaux_ctl & DDI_AUX_CTL_TIMEOUT_ERROR)
			{
				printk("Timed out\n");
				printk("DDAUX_CTL: %x\n", ddaux_ctl);
				return 0;
			}

			if(ddaux_ctl & DDI_AUX_CTL_receive_ERROR)
			{
				printk("receive error\n");
				return 0;
			}

			if(!(ddaux_ctl & DDI_AUX_CTL_DONE))
				continue;

			break;
		}

		udelay(1);
	}

	printk("DDAUX status: %x\n", igpu_mmio_read(port->device, port->ctl_reg));

	uint16_t msg_size = igpu_mmio_read(port->device, port->ctl_reg) >> 20;
	msg_size &= 0x1f;

	printk("msg_size: %u\n", msg_size);
	printk("%x\n", igpu_mmio_read(port->device, port->ctl_reg)); 
	for(unsigned int i = 0; i < msg_size; i += 4)
	{
		uint32_t *ptr = (uint32_t *) &data[i];
		*ptr = LITTLE_TO_BIG32(igpu_mmio_read(port->device,
				       port->data_base_reg + i));
		printk("data[%u]: %x\n", i, *ptr);
	}

	uint8_t st = data[0] >> 4;

	int ret = 0;
	if(st == DDI_AUX_REPLY_AUX_DEFER)
		ret = -EAGAIN;
	return ret;
}

int ddaux_do_transfers(struct i2c_adapter *adapter,
				     struct i2c_message *messages, size_t nr)
{
	while(nr--)
	{
		int st = 0;
		
		for(int i = 0; i < 1; i++)
		{do
		{
			st = ddaux_do_transfer(adapter, messages);
		} while(st < 0 && st == -EAGAIN);

		if(st < 0)
			return st;
		}

		messages++;
	}

	return 0;
}

void igd_init_displayport_i2c(struct igpu_device *dev, struct igd_displayport *port)
{
	struct i2c_adapter *adapter = &port->ddaux;

	mutex_init(&port->ddaux.mtx);

	adapter->do_batch_transfer = ddaux_do_transfers;
	adapter->name = port->name;
	adapter->priv = port;
}

int igd_init_displayport(struct igpu_device *dev)
{
	for(unsigned int i = 0; i < NR_DISPLAY_PORTS; i++)
	{
		dev->dports[i] = (igd_displayport *) zalloc(sizeof(*dev->dports[i]));
		if(!dev->dports[i])
		{
			return -ENOMEM;
		}
		
		dev->dports[i]->ctl_reg = DDI_GET_REG(DDI_AUX_CTL_BASE, i);
		dev->dports[i]->data_base_reg = DDI_GET_REG(DDI_AUX_DATA_BASE,
							    i);
		dev->dports[i]->index = i;
		dev->dports[i]->device = dev;

		/* Allocate a buffer (size for DDIX + '\0' = 5) */
		char *buf = (char *) malloc(5);
		if(!buf)
		{
			return -ENOMEM;
		}

		buf[4] = '\0';
		strcpy(buf, "DDI");
		buf[3] = 'A' + i;

		dev->dports[i]->name = buf;
	
		igd_init_displayport_i2c(dev, dev->dports[i]);
	}

	return 0;
}
