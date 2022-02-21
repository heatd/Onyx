/*
* Copyright (c) 2022 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

/* TODO: Stubs */
.global copy_to_user
.global copy_from_user
.global user_memset
.global get_user64
.global get_user32
.global strlen_user
.type get_user64, @function
.type copy_to_user,@function
.type copy_from_user,@function
.type strlen_user,@function
.type user_memset,@function
.type get_user32,@function
copy_from_user:
strlen_user:
get_user64:
get_user32:
user_memset:
copy_to_user:
    mov x0, -14
    ret
