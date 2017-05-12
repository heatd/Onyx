/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <svga.h>

#include <kernel/mutex.h>
#include <kernel/vmm.h>
#include <kernel/module.h>
#include <kernel/portio.h>
#include <kernel/video.h>
#include <kernel/compiler.h>

#include <drivers/pci.h>
MODULE_AUTHOR("Pedro Falcato");
MODULE_LICENSE(MODULE_LICENSE_MIT);
MODULE_INSERT_VERSION();

#define MPRINTF(...) printf("svga: "__VA_ARGS__)

static uint16_t io_space = 0;
static void *framebuffer = NULL;
static size_t framebuffer_size = 0;
static void *command_buffer = NULL;
static size_t command_buffer_size = 0;
static mutex_t mtx;
void svga_set_index(uint16_t index)
{
	outl(io_space + SVGA_INDEX_PORT, index);
}
void svga_write_value(uint32_t value)
{
	outl(io_space + SVGA_VALUE_PORT, value);
}
void svga_write(uint16_t index, uint32_t value)
{
	/* We need mutexes to protect a race condition 
	(i.e: writing to the index port while someone is reading from the value port) */
	mutex_lock(&mtx);
	svga_set_index(index);
	svga_write_value(value);
	mutex_unlock(&mtx);
}
uint32_t svga_read(uint16_t index)
{
	mutex_lock(&mtx);
	svga_set_index(index);
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
	size_t max_width = svga_read(SVGA_REG_MAX_WIDTH);
	size_t max_height = svga_read(SVGA_REG_MAX_HEIGHT);
	if(max_width < width)
		return -1;
	if(max_height < height)
		return -1;
	svga_write(SVGA_REG_WIDTH, width);
	svga_write(SVGA_REG_HEIGHT, height);
	svga_write(SVGA_REG_BITS_PER_PIXEL, bpp);

	return 0;
}
void *svga_get_fb(struct video_device *dev)
{
	UNUSED(dev);
	return framebuffer;
}
static struct video_ops svga_ops = 
{
	.get_fb = svga_get_fb,
	.modeset = svga_modeset
};
static struct video_device svga_device = 
{
	.ops = &svga_ops,
	.driver_string = "svga",
	.card_string = "VMWare SVGAII",
	.status = VIDEO_STATUS_INSERTED,
	.refcount = 0
};
int module_init(void)
{
	MPRINTF("initializing\n");

	/* Get a handle to the PCI device */
	PCIDevice *dev = get_pcidev_from_vendor_device(VMWARE_SVGAII_PCI_DEVICE, VMWARE_SVGAII_PCI_VENDOR);
	if(!dev)
	{
		MPRINTF("Couldn't find a valid VMware SVGAII device!\n");
		return 1;
	}
	/* Now, get the needed bars (0, 1 and 2, respectively) */
	pcibar_t *iospace_bar = pci_get_bar(dev->slot, dev->device, dev->function, SVGAII_IO_SPACE_BAR);
	pcibar_t *framebuffer_bar = pci_get_bar(dev->slot, dev->device, dev->function, SVGAII_FRAMEBUFFER_BAR);
	pcibar_t *command_buffer_bar = pci_get_bar(dev->slot, dev->device, dev->function, SVGAII_COMMAND_BUFFER_BAR);
	if(!iospace_bar)
		return 1;
	if(!framebuffer_bar)
	{
		free(iospace_bar);
		return 1;
	}
	if(!command_buffer_bar)
	{
		free(iospace_bar);
		free(framebuffer_bar);
		return 1;
	}
	io_space = (uint16_t) iospace_bar->address;
	framebuffer = (void*) (uint64_t) framebuffer_bar->address;
	framebuffer_size = framebuffer_bar->size;
	command_buffer = (void*) (uint64_t) command_buffer_bar->address;
	command_buffer_size = command_buffer_bar->size;
	MPRINTF("IO Space: %x\nsvga: Framebuffer: %p\nsvga: Command Buffer: %p\n", io_space, framebuffer, command_buffer);

	/* Map the physical addresses in the virtual address space */
	framebuffer = dma_map_range(framebuffer, framebuffer_size, VM_WRITE | VM_GLOBAL | VM_NOEXEC);
	
	if(!framebuffer)
	{
		free(iospace_bar);
		free(framebuffer_bar);
		free(command_buffer_bar);
		return 1;
	}
	framebuffer_size = framebuffer_bar->size;
	command_buffer = dma_map_range(command_buffer, command_buffer_size, VM_WRITE | VM_GLOBAL | VM_NOEXEC);
	
	if(!command_buffer)
	{
		free(iospace_bar);
		free(framebuffer_bar);
		free(command_buffer_bar);
		return 1;	
	}

	/* Finally, enable SVGA */
	svga_write(SVGA_REG_ENABLE, 1);

	/* Note that we need to set the video mode right now, as if we don't, it will fallback to the lowest VGA res */
	struct video_mode *mode = video_get_videomode(video_get_main_adapter());
	svga_modeset(mode->width, mode->height, mode->bpp, NULL);
	
	/* Set this video adapter as the main adapter */
	video_set_main_adapter(&svga_device);

	/* Free memory and return */
	free(iospace_bar);
	free(framebuffer_bar);
	free(command_buffer_bar);
	MPRINTF("Successfully initialized the device!\n");
	return 0;
}
int module_fini(void)
{
	return 0;
}