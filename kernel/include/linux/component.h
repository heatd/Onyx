#ifndef _LINUX_COMPONENT_H
#define _LINUX_COMPONENT_H

#include <linux/device.h>

struct component_ops {
	/**
	 * @bind:
	 *
	 * Called through component_bind_all() when the aggregate driver is
	 * ready to bind the overall driver.
	 */
	int (*bind)(struct device *comp, struct device *master,
		    void *master_data);
	/**
	 * @unbind:
	 *
	 * Called through component_unbind_all() when the aggregate driver is
	 * ready to bind the overall driver, or when component_bind_all() fails
	 * part-ways through and needs to unbind some already bound components.
	 */
	void (*unbind)(struct device *comp, struct device *master,
		       void *master_data);
};

#endif
