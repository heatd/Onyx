/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#include <logging.h>

#include <iostream>

int main(int argc, char **argv, char **envp)
{
    Logger log;
    log.RedirectOutStreams();

    return 0;
}
