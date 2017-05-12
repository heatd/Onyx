/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifdef __is_spartix_kernel
int errno = 0;
#else
/*__thread*/ int errno = 0;
#endif
