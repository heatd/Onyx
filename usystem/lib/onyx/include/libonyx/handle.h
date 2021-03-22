/*
* Copyright (c) 2021 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _LIBONYX_HANDLE_H
#define _LIBONYX_HANDLE_H

#include <onyx/public/handle.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Opens a handle to a resource
 * 
 * @param resource_type The type of resource to be opened (specified in onyx/public/handle.h)
 * @param id The id of the resource (can be a regular old ID, or even a pointer, depending on the resource)
 * @param flags Flags passed to the handle opening code, that affect handle opening and the resulting fd
 * @return int The fd that contains the handle.
 */
int onx_handle_open(unsigned int resource_type, unsigned long id, int flags);

/**
 * @brief Closes the specified handle
 * 
 * NOTE: This is a blackbox, but is implemented at the moment of writing as a wrapper over close(3)
 * @param handle Handle
 */
void onx_handle_close(int handle);


/**
 * @brief Retrieves miscellaneous info on a handle
 * 
 * @param handle Handle to be queried
 * @param buffer The destination buffer
 * @param len The length of the buffer
 * @param what Implementation defined
 * @param howmany How many elements there where to be retrieved
 * @param arg Implementation defined
 * @return ssize_t The length written, or -1 on error
 */
ssize_t onx_handle_query(int handle, void *buffer, ssize_t len, unsigned long what, size_t *howmany,
                                        void *arg);

#ifdef __cplusplus
}
#endif

#endif
