/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdint.h>

#ifndef __avl_tree_defined_
typedef struct avl_node avl_node_t;
#define __avl_tree_defined_
#endif

int avl_get_height(avl_node_t *ptr);
void avl_balance_tree(avl_node_t **t);