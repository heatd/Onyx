/*----------------------------------------------------------------------
 * Copyright (C) 2017 Pedro Falcato
 *
 * This file is part of Onyx, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <stdint.h>

#ifndef __avl_tree_defined_
typedef struct avl_node avl_node_t;
#define __avl_tree_defined_
#endif

int avl_get_height(avl_node_t *ptr);
void avl_balance_tree(avl_node_t **t);