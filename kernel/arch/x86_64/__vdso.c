/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
struct vdso_info
{
	char name[255];
	char kernel[60];
	char architecture[60];
};
static struct vdso_info info =
{
	.name = "onyx-vdso",
	.kernel = "onyx-0.4",
	.architecture = "x86_64"
};
static struct vdso_info *__vdso_get_vdso_info(void)
{
	return &info;
}
