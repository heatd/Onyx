#ifndef _LINUX_PROPERTY_H
#define _LINUX_PROPERTY_H

#include <stdbool.h>

#include <linux/err.h>

struct fwnode_handle {
    struct fwnode_handle *secondary;
};

#define fwnode_handle_put(handle) ((void) (handle))

bool fwnode_device_is_available(const struct fwnode_handle *handle);

static inline
struct fwnode_handle *fwnode_find_reference(const struct fwnode_handle *fwnode,
					    const char *name,
					    unsigned int index)
{
    return ERR_PTR(-ENOENT);
}

static inline
bool fwnode_property_present(const struct fwnode_handle *fwnode,
			     const char *propname)
{
    return false;
}

#endif
