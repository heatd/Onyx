/*
 * Copyright (c) 2021 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <logging.h>

#include <iostream>

int main(int argc, char **argv)
{
    (void) argc;
    (void) argv;
    Logger log;
    log.RedirectOutStreams();

    return 0;
}
