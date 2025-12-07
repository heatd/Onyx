#ifndef _LINUX_OF_GRAPH_H
#define _LINUX_OF_GRAPH_H

struct device_node;

struct of_endpoint {
	unsigned int port;
	unsigned int id;
	const struct device_node *local_node;
};

#endif
