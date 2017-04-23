/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _SH_LOGIN_H
#define _SH_LOGIN_H

#include <stdbool.h>

#define DEFAULT_LOGIN_SCRIPT_PATH "/etc/" /* Default(more like fallback though) path of the login script executed by tash */
#define TASH_LOGIN_SCRIPT ".tash_login" /* Name of the login script executed by tash */
void tash_do_login(void);

/* Returns true if it is a login shell */
_Bool tash_is_login(void);
#endif