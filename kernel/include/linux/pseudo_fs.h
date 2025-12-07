#ifndef _LINUX_PSEUDO_FS_H
#define _LINUX_PSEUDO_FS_H

#include <linux/fs_context.h>

struct pseudo_fs_context *init_pseudo(struct fs_context *fc,
				      unsigned long magic);

#endif
