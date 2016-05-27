/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
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
	TTY& operator << (const char* str)
	{
		WriteString(str);
		return *this;
	}
	void Scroll();
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
