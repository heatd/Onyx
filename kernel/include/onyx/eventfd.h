/*
 * Copyright (c) 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_EVENTFD_H
#define _ONYX_EVENTFD_H

struct eventfd;

void eventfd_ctx_put(struct eventfd *ev);
struct eventfd *eventfd_ctx_fdget(int fd);
void eventfd_signal(struct eventfd *ctx);

#endif
