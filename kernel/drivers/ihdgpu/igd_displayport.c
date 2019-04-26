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

int ddaux_do_transfers(struct i2c_adapter *adapter,
				     struct i2c_message *messages, size_t nr);

#define LITTLE_TO_BIG32(n) ((n >> 24) & 0xFF) | ((n << 8) & 0xFF0000) | \
			   ((n >> 8) & 0xFF00) | ((n << 24) & 0xFF000000)

int ddaux_do_transfer(struct i2c_adapter *adapter,
				     struct i2c_message *message)
{
	struct igd_displayport *port = adapter->priv;

	uint8_t data[20];
	uint8_t cmd;
	uint16_t size = 4;

	if(message->write)
		cmd = DP_AUX_I2C_WRITE;
	else
		cmd = DP_AUX_I2C_READ;

	data[0] = (uint8_t) ((cmd << 4));
	data[1] = (uint8_t) ((message->addr >> 8));
	data[2] = (uint8_t) ((message->addr)); 
	data[3] = (message->length - 1);

	if(message->write)
	{
		size += message->length;
		memcpy(data + 4, message->buffer, message->length);
	}

	for(unsigned int i = 0; i < size; i += 4)
	{
		uint32_t *ptr = (uint32_t *) &data[i];
		igpu_mmio_write(port->device, port->data_base_reg + i,
				LITTLE_TO_BIG32(*ptr));
	}

	uint32_t ddaux_ctl = 0;

	ddaux_ctl |= DDI_AUX_CTL_MESSAGE_SIZE(size);
	ddaux_ctl |= DDI_AUX_CTL_TIMEOUT_1600US;
	ddaux_ctl |= DDI_AUX_CTL_DONE;
	ddaux_ctl |= DDI_AUX_CTL_RECIEVE_ERROR;
	ddaux_ctl |= DDI_AUX_CTL_TIMEOUT_ERROR;
	ddaux_ctl |= DDI_AUX_CTL_SEND_BUSY;
	ddaux_ctl |= DDI_AUX_CTL_IRQ_ON_DONE; /* 1 means disabled */
	ddaux_ctl |= 225;

	printk("Writing ddaux %x\n", ddaux_ctl);

	igpu_mmio_write(port->device, port->ctl_reg, ddaux_ctl);

	for(int i = 0; i < 1000; i++)
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

			if(ddaux_ctl & DDI_AUX_CTL_RECIEVE_ERROR)
			{
				printk("Recieve error\n");
				return 0;
			}

			if(!(ddaux_ctl & DDI_AUX_CTL_DONE))
				continue;

			break;
		}

		sched_sleep(1);	
	}

	printk("DDAUX status: %x\n", igpu_mmio_read(port->device, port->ctl_reg));

	uint16_t msg_size = igpu_mmio_read(port->device, port->ctl_reg) >> 20;
	msg_size &= 0x1f;

	printk("msg_size: %u\n", msg_size);

	for(unsigned int i = 0; i < msg_size; i += 4)
	{
		uint32_t *ptr = (uint32_t *) &data[i];

		*ptr = LITTLE_TO_BIG32(igpu_mmio_read(port->device,
				       port->data_base_reg + i));
	}

	uint8_t *ptr = data + 4;

	return 0;
}

int ddaux_do_transfers(struct i2c_adapter *adapter,
				     struct i2c_message *messages, size_t nr)
{
	while(nr--)
	{
		int st = ddaux_do_transfer(adapter, messages);

		if(st < 0)
			return st;

		messages++;
	}

	return 0;
}

void igd_init_displayport_i2c(struct igpu_device *dev, struct igd_displayport *port)
{
	struct i2c_adapter *adapter = &port->ddaux;

	adapter->do_batch_transfer = ddaux_do_transfers;
	adapter->name = port->name;
	adapter->priv = port;
}

int igd_init_displayport(struct igpu_device *dev)
{
	for(unsigned int i = 0; i < NR_DISPLAY_PORTS; i++)
	{
		dev->dports[i] = zalloc(sizeof(*dev->dports[i]));
		if(!dev->dports[i])
		{
			return -ENOMEM;
		}
		
		dev->dports[i]->ctl_reg = DDI_GET_REG(DDI_AUX_CTL_BASE, i);
		dev->dports[i]->data_base_reg = DDI_GET_REG(DDI_AUX_DATA_BASE,
							    i);
		dev->dports[i]->index = i;
		dev->dports[i]->device = dev;

		/* Allocate a buffer with size for DDIX\0 */
		char *buf = malloc(5);
		if(!buf)
		{
			return -ENOMEM;
		}

		buf[4] = '\0';
		strcpy(buf, "DDI");
		buf[3] = 'A' + i;

		dev->dports[i]->name = buf;
	
		igd_init_displayport_i2c(dev, dev->dports[i]);

		uint8_t edid[256];
		struct i2c_message message;
		message.addr = 0x50;
		message.buffer = (uint8_t *) &edid;
		message.length = sizeof(struct i2c_message);
		message.transfered = 0;
		message.write = false;
	
		i2c_transaction(&dev->dports[i]->ddaux, &message, 1);
	}

	return 0;
}