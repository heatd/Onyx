/* Copyright 2016 Pedro Falcato

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http ://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
/**************************************************************************
 *
 *
 * File: devfs.cpp
 *
 * Description: Devfs initialization, and mounting
 *
 * Date: 20/3/2016
 *
 *
 **************************************************************************/
#include <kernel/devfs.h>

fs_node_t* devfs_init()
{
	fs_node_t* devfs = open_fs(NULL,0,0,"/dev/");
	if(!devfs)
		abort();
	return devfs;
}
