/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <commands.h>

#include <iostream>

#include <backend/database.h>

namespace pkgman
{

namespace commands
{

int list(std::span<char *> options)
try
{
    auto db = backend::open_database(true);

    auto packages = db.get_package_list();

    for (auto &p : packages)
    {
    }

    return 0;
}
catch (const std::exception &e)
{
    std::cerr << "Error: " << e.what() << "\n";
    return 1;
}

} // namespace commands
} // namespace pkgman
