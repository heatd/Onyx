#ifndef _LINUX_DEBUGFS_H
#define _LINUX_DEBUGFS_H

#include <onyx/err.h>

#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/compiler_types.h>

struct debugfs_reg32 {
	char *name;
	unsigned long offset;
};

struct debugfs_regset32 {
	const struct debugfs_reg32 *regs;
	int nregs;
	void __iomem *base;
	struct device *dev;	/* Optional device for Runtime PM */
};

static inline struct dentry *debugfs_create_file(const char *name, umode_t mode,
					struct dentry *parent, void *data,
					const void *fops)
{
	return ERR_PTR(-ENODEV);
}


#endif
