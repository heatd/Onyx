#ifndef _LINUX_UACCESS_H
#define _LINUX_UACCESS_H

#include <onyx/user.h>
#include <linux/minmax.h>
#include <linux/string.h>

#define put_user(x, ptr) ({(void) (ptr); -EFAULT;})
#define get_user(dst, ptr) ({(void) (ptr); -EFAULT;})

#endif
