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
#pragma once
#include <stddef.h>
#include <stdint.h>
class TTY
{
public:
	unsigned int max_row;
	static const unsigned int max_row_fallback = 1024/16;
	unsigned int max_column;
	static const unsigned int max_column_fallback = 768/9;
	void PutChar(char c);
	void Write(const char *data, size_t size);
	void WriteString(const char *data);
	void SetColor(int color);
	void Init(void);
private:
	size_t terminal_row;
	size_t terminal_column;
	uint32_t last_x;
	uint32_t last_y;
	int terminal_color;
	void PutEntryAt(char c, uint32_t color, size_t column, size_t row);

};
/* Global pointer to a TTY object */
extern TTY* global_terminal;