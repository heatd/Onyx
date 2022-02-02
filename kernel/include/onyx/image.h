/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#ifndef _ONYX_IMAGE_H
#define _ONYX_IMAGE_H

#define RISCV_IMAGE_MAGIC  "RISCV\0\0\0"
#define RISCV_IMAGE_MAGIC2 "RSC\x05"

// Defined as (major << 16 | minor)
#define RISCV_HEADER_VERSION (0 << 16 | 2)

#define RISCV_LOAD_ADDRESS 0x80080000

#ifndef __ASSEMBLER__

#include <stdint.h>

namespace platform
{

// This format first appeared for linux and is expected by lots of bootloaders.
// The format is shared between at least ARM64 and RISCV and details are found
// in asm/image.h, in the riscv and arm64 code.
struct image_header
{
    uint32_t code[2];
    uint64_t load_offset;
    uint64_t image_size;
    uint64_t flags;
    uint32_t version;
    uint32_t res0;
    uint64_t res1;
    uint64_t magic0;
    uint32_t magic1;
    uint32_t res3;
};

} // namespace platform

#endif

#endif
