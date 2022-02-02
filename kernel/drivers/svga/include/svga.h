/*
 * Copyright (c) 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#ifndef _VMWARE_SVGAII_H
#define _VMWARE_SVGAII_H

#include <stdint.h>

#include <onyx/mutex.h>
#include <onyx/video.h>

#include <pci/pci.h>

#define VMWARE_SVGAII_PCI_VENDOR 0x15AD
#define VMWARE_SVGAII_PCI_DEVICE 0x0405

#define SVGAII_IO_SPACE_BAR       0
#define SVGAII_FRAMEBUFFER_BAR    1
#define SVGAII_COMMAND_BUFFER_BAR 2

#define SVGA_INDEX_PORT     0x0
#define SVGA_VALUE_PORT     0x1
#define SVGA_BIOS_PORT      0x2
#define SVGA_IRQSTATUS_PORT 0x8

#define SVGA_REG_ID             0
#define SVGA_REG_ENABLE         1
#define SVGA_REG_WIDTH          2
#define SVGA_REG_HEIGHT         3
#define SVGA_REG_MAX_WIDTH      4
#define SVGA_REG_MAX_HEIGHT     5
#define SVGA_REG_DEPTH          6
#define SVGA_REG_BITS_PER_PIXEL 7
#define SVGA_REG_PSEUDOCOLOR    8
#define SVGA_REG_RED_MASK       9
#define SVGA_REG_GREEN_MASK     10
#define SVGA_REG_BLUE_MASK      11
#define SVGA_REG_BYTES_PER_LINE 12
#define SVGA_REG_FB_START       13 /* (Deprecated) */
#define SVGA_REG_FB_OFFSET      14
#define SVGA_REG_VRAM_SIZE      15
#define SVGA_REG_FB_SIZE        16
#define SVGA_REG_CAPABILITIES   17
#define SVGA_REG_MEM_START      18
#define SVGA_REG_MEM_END        19
#define SVGA_REG_CONFIG_DONE    20
#define SVGA_REG_SYNC           21
#define SVGA_REG_BUSY           22
#define SVGA_REG_NUM_REGS       30
enum
{
    SVGA_FIFO_MIN = 0,
    SVGA_FIFO_MAX,
    SVGA_FIFO_NEXT_CMD,
    SVGA_FIFO_STOP,
    SVGA_FIFO_CAPABILITIES,
    SVGA_FIFO_FLAGS,
    SVGA_FIFO_FENCE,
};

typedef enum
{
    SVGA_CMD_INVALID_CMD = 0,
    SVGA_CMD_UPDATE = 1,
    SVGA_CMD_RECT_COPY = 3,
    SVGA_CMD_DEFINE_CURSOR = 19,
    SVGA_CMD_DEFINE_ALPHA_CURSOR = 22,
    SVGA_CMD_UPDATE_VERBOSE = 25,
    SVGA_CMD_FRONT_ROP_FILL = 29,
    SVGA_CMD_FENCE = 30,
    SVGA_CMD_ESCAPE = 33,
    SVGA_CMD_DEFINE_SCREEN = 34,
    SVGA_CMD_DESTROY_SCREEN = 35,
    SVGA_CMD_DEFINE_GMRFB = 36,
    SVGA_CMD_BLIT_GMRFB_TO_SCREEN = 37,
    SVGA_CMD_BLIT_SCREEN_TO_GMRFB = 38,
    SVGA_CMD_ANNOTATION_FILL = 39,
    SVGA_CMD_ANNOTATION_COPY = 40,
    SVGA_CMD_DEFINE_GMR2 = 41,
    SVGA_CMD_REMAP_GMR2 = 42,
    SVGA_CMD_MAX
} svga_fifo_cmd_id;

class SvgaDevice
{
private:
    uint16_t io_space;
    /* The physical address of the framebuffer */
    void *framebuffer_raw;
    /* Virtual address mapping of the framebuffer */
    void *framebuffer;
    size_t framebuffer_size;
    uint32_t *command_buffer;
    size_t command_buffer_size;
    uint32_t num_regs;
    struct mutex mtx;
    struct mutex fifo_lock;
    struct video_mode mode;
    pci::pci_device *dev;

public:
    void write_index(uint16_t index);
    void write_value(uint32_t value);
    void write(uint16_t index, uint32_t value);
    uint32_t read(uint16_t index);
    int modeset(unsigned int width, unsigned int height, unsigned int bpp);
    SvgaDevice(pci::pci_device *dev) : dev(dev)
    {
        mutex_init(&mtx);
        mutex_init(&fifo_lock);
    }

    void enable();
    void setup_fifo();
    void wait_for_fifo(size_t len);
    void send_command_fifo(void *command, size_t len);
    int add_bar(pci::pci_bar bar, int index);
    void *get_framebuffer()
    {
        return framebuffer;
    }
    struct video_mode *get_video_mode(void)
    {
        return &mode;
    }
    void set_video_mode(struct video_mode *video)
    {
        memcpy(&mode, video, sizeof(struct video_mode));
    }
};
#endif
