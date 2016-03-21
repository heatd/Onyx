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
#include <string.h>

int memcmp(const void *aptr, const void *bptr, size_t size)
{
	const unsigned char *a = (const unsigned char *) aptr;
	const unsigned char *b = (const unsigned char *) bptr;
	for (size_t i = 0; i < size; i++)
		if (a[i] < b[i])
			return -1;
		else if (b[i] < a[i])
			return 1;
	return 0;
}
