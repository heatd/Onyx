#ifndef _ASM_IOCTL_H
#define _ASM_IOCTL_H

#include <uapi/ioctl.h>

#define _IOC_NRBITS	8
#define _IOC_TYPEBITS	8
/* size has the upper 16 bits, minus WRITE|READ (top 2 bits) */
#define _IOC_SIZEBITS	14

#define _IOC_NRMASK ((1UL << (_IOC_NRBITS)) - 1)
#define _IOC_TYPEMASK ((1UL << (_IOC_TYPEBITS)) - 1)
#define _IOC_SIZEMASK ((1UL << (_IOC_SIZEBITS)) - 1)

#define _IOC_NR(n) ((n) & _IOC_NRMASK)
#define _IOC_TYPE(n) (((n) >> 8) & _IOC_TYPEMASK)
#define _IOC_SIZE(n) (((n) >> 16) & _IOC_SIZEMASK)

#define IOC_IN		(_IOC_WRITE << 30)
#define IOC_OUT		(_IOC_READ << 30)
#endif
