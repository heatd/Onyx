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
#include <ctype.h>
/* Damn thats a long macro name... */
#define ASCII_DIFF_BETWEEN_LOWER_AND_UPPER 32
int tolower(int c)
{
	/* If the ascii character code is between 91 and 64, its uppercase */
	if(c < 91 && c > 64) {
		return c + ASCII_DIFF_BETWEEN_LOWER_AND_UPPER;
	}
	return c;
}
int toupper(int c)
{
	if(c > 96 && c < 123) {
		return c - ASCII_DIFF_BETWEEN_LOWER_AND_UPPER;
	}
	return c;
}
int _toupper(int c)
{
	return toupper(c);
}
int _tolower(int c)
{
	return tolower(c);
}
int isalpha(int c)
{
    return toupper(c) || tolower(c);
}
