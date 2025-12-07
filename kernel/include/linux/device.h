#ifndef _LINUX_DEVICE_H
#define _LINUX_DEVICE_H

#include <linux/types.h>
#include <linux/bits.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/property.h>

struct device_node;

#define device linux_device

#include <onyx/dev_printk.h>
#include <onyx/majorminor.h>

/* don't bother... */
#define old_encode_dev(dev) (0)
#define dev_WARN_ONCE(...) (false)
#define dev_warn_once(...) do {} while(0)

struct device_type {
	const char *name;
};

struct device_dma_parameters {
	/*
	 * a low level driver may set these to teach IOMMU code about
	 * sg limitations.
	 */
	unsigned int max_segment_size;
	unsigned int min_align_mask;
	unsigned long segment_boundary_mask;
};

struct device
{
    dma_addr_t *dma_mask;
    dma_addr_t coherent_dma_mask;
    struct device_dma_parameters *dma_parms;
	void *drv_data;
	bool is_pci;
	struct device_type *type;
	struct fwnode_handle *fwnode;
};

#define dev_fwnode(dev) ((dev)->fwnode)
#define device_property_present(dev, prop) fwnode_property_present((dev)->fwnode, prop)

int __devm_add_action_or_reset(struct device *dev, void (*action)(void *),
					     void *data, const char *name);
#define devm_add_action_or_reset(dev, action, data) \
	__devm_add_action_or_reset(dev, action, data, #action)

void devm_release_action(struct device *dev, void (*action)(void *), void *data);

static inline int dev_err_probe(const struct device *dev, int err, const char *fmt, ...)
{
	return err;
}

struct device *get_device(struct device *dev);
void put_device(struct device *dev);
int device_add(struct device *dev);
void device_del(struct device *dev);
bool device_is_registered(struct device *dev);

static inline void dev_set_drvdata(struct device *dev, void *data)
{
	dev->drv_data = data;
}

static inline void *dev_get_drvdata(struct device *dev)
{
	return dev->drv_data;
}

const char *dev_name(const struct device *dev);

static inline int dev_to_node(struct device *dev)
{
	return -1;
}

#endif
