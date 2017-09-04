/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <onyx/id.h>
#include <onyx/spinlock.h>

#define NAME_MAX 256
struct ids *list;
static spinlock_t list_lock;
static void append_to_list(struct ids *p)
{
	acquire_spinlock(&list_lock);
	if(!list)
		list = p;
	else
	{
		struct ids *l = list;
		while(list->next) list = list->next;
		l->next = p;
	}
	release_spinlock(&list_lock);
}
struct ids *get_ids_from_name(const char *name)
{
	for(struct ids *l = list; l; l = l->next)
	{
		if(!strcmp(l->name, name))
			return l;
	}
	return NULL;
}
struct ids *idm_add(const char *name, uintmax_t min_id, uintmax_t upper_limit)
{
	struct ids 	*id;

	assert(min_id < upper_limit);
	assert(name != NULL);
	id = zalloc(sizeof(struct ids));
	if(!id)
		goto cleanup_and_error;
	if(!(id->name = strdup(name)))
		goto cleanup_and_error;
	id->id = min_id;
	id->upper_limit = upper_limit;
	append_to_list(id);
	return id;
cleanup_and_error:
	if(id)
	{
		free(id->name);
	}
	free(id);
	return NULL;
}
uintmax_t idm_get_id(struct ids *ids)
{
	assert(ids != NULL);
	uintmax_t id = ids->id++;
	if(id >= ids->upper_limit)
		return errno = ERANGE, -1;
	return id;
}
uintmax_t idm_get_id_from_name(const char *name)
{
	assert(name != NULL);
	struct ids *id = get_ids_from_name(name);
	if(!id)
		return errno = ENOENT, -1;
	return idm_get_id(id);
}
const char *idm_get_device_letter(struct ids *ids)
{
	/* Max name is Zz + 1 char for \0 */
	char buffer[3];
	assert(ids != NULL);
	uintmax_t id = idm_get_id(ids);
	if(id == (uintmax_t) -1)
		return NULL;
	if(id > 26)
	{
		buffer[0] = 'A' + id / 26;
		buffer[1] = 'a' + id % 26;
	}
	else
	{
		buffer[0] = 'a' + id;
		buffer[1] = '\0';
	}
	buffer[2] = '\0';
	return strdup(buffer);
}
