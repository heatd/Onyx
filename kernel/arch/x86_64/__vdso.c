/*----------------------------------------------------------------------
 * Copyright (C) 2017 Pedro Falcato
 *
 * This file is part of Onyx, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
struct vdso_info
{
	char name[255];
	char kernel[60];
	char architecture[60];
};
static struct vdso_info info =
{
	.name = "onyx-vdso",
	.kernel = "onyx-0.3",
	.architecture = "x86_64"
};
static struct vdso_info *__vdso_get_vdso_info(void)
{
	return &info;
}
