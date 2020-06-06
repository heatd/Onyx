/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include "include/svga.h"
#include <limits.h>

#include <onyx/memory.hpp>
#include <onyx/mutex.h>
#include <onyx/vm.h>
#include <onyx/module.h>
#include <onyx/port_io.h>
#include <onyx/video.h>
#include <onyx/compiler.h>
#include <onyx/scheduler.h>


extern "C"
{
#include <onyx/framebuffer.h>
}

#include <pci/pci.h>

MODULE_AUTHOR("Pedro Falcato");
MODULE_LICENSE(MODULE_LICENSE_MIT);
MODULE_INSERT_VERSION();

#define MPRINTF(...) printf("svga: " __VA_ARGS__)

static unique_ptr<SvgaDevice> device;
void SvgaDevice::write_index(uint16_t index)
{
	outl(io_space + SVGA_INDEX_PORT, index);
}

void SvgaDevice::write_value(uint32_t value)
{
	outl(io_space + SVGA_VALUE_PORT, value);
}

void SvgaDevice::write(uint16_t index, uint32_t value)
{
	/* We need mutexes to protect a race condition 
	(i.e: writing to the index port while someone is reading from the value port) */
	mutex_lock(&mtx);
	write_index(index);
	write_value(value);
	mutex_unlock(&mtx);
}

uint32_t SvgaDevice::read(uint16_t index)
{
	mutex_lock(&mtx);
	write_index(index);
	uint32_t ret = inl(io_space + SVGA_VALUE_PORT);
	mutex_unlock(&mtx);
	return ret;
}

int svga_modeset(unsigned int width, unsigned int height, unsigned int bpp, struct video_device *dev)
{
	UNUSED(dev);
	/* To set the video mode with SVGA, we need to write the width to _REG_WIDTH, height to _REG_HEIGHT,
	   and bpp to _REG_BITS_PER_PIXEL
	*/
	size_t max_width = device->read(SVGA_REG_MAX_WIDTH);
	size_t max_height = device->read(SVGA_REG_MAX_HEIGHT);
	if(max_width < width)
		return -1;
	if(max_height < height)
		return -1;
	device->write(SVGA_REG_WIDTH, width);
	device->write(SVGA_REG_HEIGHT, height);
	device->write(SVGA_REG_BITS_PER_PIXEL, bpp);
	
	struct video_mode mode;
	mode.width = width;
	mode.height = height;
	mode.bpp = bpp;
	mode.pitch = width * (bpp / CHAR_BIT);
	device->set_video_mode(&mode);
	return 0;
}

int SvgaDevice::add_bar(struct pci_bar bar, int index)
{
	switch(index)
	{
		case SVGAII_IO_SPACE_BAR:
		{
			io_space = bar.address;
			return 0;
		}
		case SVGAII_FRAMEBUFFER_BAR:
		{
			framebuffer_raw = (void*) bar.address;
			framebuffer = mmiomap(
				framebuffer_raw,
				bar.size,
				VM_WRITE | VM_NOEXEC | VM_WC);
			if(!framebuffer)
				return -1;
			framebuffer_size = bar.size;
			return 0;
		}
		case SVGAII_COMMAND_BUFFER_BAR:
		{
			command_buffer = (uint32_t*) mmiomap((void*) 
						     (uintptr_t) bar.address,
						     bar.size,
						     VM_WRITE | VM_NOEXEC | VM_NOCACHE);
			if(!command_buffer)
				return -1;
			command_buffer_size = bar.size;
			return 0; 
		}
	}
	return 0;
}

void SvgaDevice::enable(void)
{
	num_regs = read(SVGA_REG_NUM_REGS);
	write(SVGA_REG_ENABLE, 1);
}

void SvgaDevice::setup_fifo(void)
{
	/* TODO: Broken, freezes the GPU */
#if 0
	/* TODO: Setup the command fifo in a better way, this is too minimal */
	command_buffer[SVGA_FIFO_MIN] = num_regs * 4;
	command_buffer[SVGA_FIFO_MAX] = num_regs * 4 + (10 * 1024);
	command_buffer[SVGA_FIFO_NEXT_CMD] = num_regs * 4;
	command_buffer[SVGA_FIFO_STOP] = num_regs * 4;
	
	/* Now, enable the command FIFO */
	write(SVGA_REG_CONFIG_DONE, 1);
#endif
}

void SvgaDevice::wait_for_fifo(size_t len)
{
	while(1)
	{
		if(command_buffer[SVGA_FIFO_STOP] == command_buffer[SVGA_FIFO_NEXT_CMD])
		{
			command_buffer[SVGA_FIFO_STOP] = num_regs * 4;
			command_buffer[SVGA_FIFO_NEXT_CMD] = num_regs * 4;
			return;
		}
		if(command_buffer[SVGA_FIFO_MAX] - command_buffer[SVGA_FIFO_STOP] >= len)
			return;
		sched_yield();
	}
}

void SvgaDevice::send_command_fifo(void *command, size_t len)
{
	mutex_lock(&fifo_lock);

	/* Firstly, we need to wait for the fifo to have enough space */
	wait_for_fifo(len);

	/* Now copy the command in and increment the FIFO_STOP */
	uint32_t *fifo = command_buffer + (command_buffer[SVGA_FIFO_STOP] / sizeof(uint32_t));
	memcpy(fifo, command, len);
	command_buffer[SVGA_FIFO_STOP] += len;
}

extern "C"
{

int svga_probe(struct device *_dev)
{
	struct pci_device *dev = (struct pci_device *) _dev;

	device = make_unique<SvgaDevice>(dev);
	if(!device)
		return 1;
	/* Now, get the needed bars (0, 1 and 2, respectively) */
	struct pci_bar iospace_bar, framebuffer_bar, command_buffer_bar;

	if(pci_get_bar(dev, SVGAII_IO_SPACE_BAR, &iospace_bar) < 0)
		return -1;
	if(pci_get_bar(dev, SVGAII_FRAMEBUFFER_BAR, &framebuffer_bar) < 0)
		return -1;
	if(pci_get_bar(dev, SVGAII_COMMAND_BUFFER_BAR, &command_buffer_bar) < 0)
		return -1;

	
	if(device->add_bar(iospace_bar, SVGAII_IO_SPACE_BAR) < 0)
	{
		return 1;
	}

	if(device->add_bar(framebuffer_bar, SVGAII_FRAMEBUFFER_BAR) < 0)
	{
		return 1;
	}

	if(device->add_bar(command_buffer_bar, SVGAII_COMMAND_BUFFER_BAR) < 0)
	{
		return 1;
	}

	/* Finally, enable SVGA */
	device->enable();

	/* Note that we need to set the video mode right now, as if we don't,
	 it will fallback to the lowest VGA res */
	struct framebuffer *fb = get_primary_framebuffer();
	svga_modeset(fb->width, fb->height, fb->bpp, NULL);

	/* Setup the command FIFO */
	device->setup_fifo();

	/* Set this video adapter as the main adapter */
	//video_set_main_adapter(&svga_device);

	MPRINTF("Successfully initialized the device!\n");
	return 0;
}

static struct pci_id svga_dev_ids[] = 
{
	{ PCI_ID_DEVICE(VMWARE_SVGAII_PCI_VENDOR, VMWARE_SVGAII_PCI_DEVICE, NULL) },
	{ 0 }
};

static struct driver svga_driver
{
	.name = "svga",
	.devids = &svga_dev_ids,
	.probe = svga_probe
};

static int svga_init(void)
{
	MPRINTF("initializing\n");

	pci_bus_register_driver(&svga_driver);
	return 0;
}

static int svga_fini(void)
{
	return 0;
}

MODULE_INIT(svga_init);
MODULE_FINI(svga_fini);

}
