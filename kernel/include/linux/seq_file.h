#ifndef _LINUX_SEQ_FILE_H
#define _LINUX_SEQ_FILE_H

#include <onyx/seq_file.h>
#include <linux/string.h>

#define file_operations file_ops

#define DEFINE_SHOW_ATTRIBUTE(__name)					\
static int __name ## _open(struct file *file)	\
{									\
	return single_open(file, __name ## _show, file->f_ino->i_helper);	\
}									\
									\
static const struct file_operations __name ## _fops = {			\
	.on_open		= __name ## _open,				\
	.read_iter		= seq_read_iter,					\
	.llseek		= seq_lseek,					\
	.release	= single_release,				\
}

#endif
