/*
 * Copyright (c) 2019 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#include <errno.h>
#include <stdlib.h>

#include "igpu_drv.h"
#include "intel_regs.h"

void igd_set_trans_regs(struct igd_transcoder *trans)
{
    uint32_t offset = PIPE_OFFSET_PER_PIPE * trans->name;
    if (trans->name == TRANS_EDP)
        offset = PIPE_OFFSET_EDP;

    trans->htotal_reg = PIPE_HTOTAL + offset;
    trans->hsync_reg = PIPE_HSYNC + offset;
    trans->vtotal_reg = PIPE_VTOTAL + offset;
    trans->vsync_reg = PIPE_VSYNC + offset;
    trans->hblank_reg = PIPE_HBLANK + offset;
    trans->vblank_reg = PIPE_VBLANK + offset;
}

int igd_init_transcoders(struct igpu_device *dev)
{
    for (unsigned int i = 0; i < NR_TRANSCODERS; i++)
    {
        struct igd_transcoder *trans = zalloc(sizeof(*trans));

        if (!trans)
            return -1;

        trans->name = (enum TRANSCODER_NAME) i;
        igd_set_trans_regs(trans);
        dev->transcoders[i] = trans;
    }

    return 0;
}