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
char* strstr(char *str, char *substr)
{
	  while (*str)
	  {
		    char *begin = str;
		    char *pattern = substr;

		    // If first character of sub string match, check for whole string
		    while (*str && *pattern && *str == *pattern)
			{
			      str++;
			      pattern++;
		    }
		    // If complete sub string match, return starting address
		    if (!*pattern)
		    	  return begin;

		    str = begin + 1;	// Increament main string
	  }
	  return 0;
}
