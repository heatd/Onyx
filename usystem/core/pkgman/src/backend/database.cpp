/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#include <fcntl.h>
#include <filesystem.h>
#include <unistd.h>

#include <filesystem>
#include <system_error>

#include <backend/database.h>

namespace pkgman
{

namespace backend
{

database::database(const std::string& path, bool readonly)
    : path{path}, fd{}, rdonly{readonly}, packages{}
{
    int flags = 0;

    if (readonly)
        flags |= O_RDONLY;
    else
        flags |= O_RDWR;

    fd = ::open(path.c_str(), flags);

    if (fd < 0)
        throw std::system_error(errno, std::generic_category(), "Failed to open the database");

    if (!readonly)
        lock_database();
}

database::~database()
{
    if (!rdonly)
        unlock_database();
}

void database::lock_database()
{
    int lock = ::openat(fd, "db.lock", O_RDWR | O_CREAT | O_EXCL, 0644);

    if (lock < 0)
        throw std::system_error(errno, std::generic_category(),
                                "Failed to lock the database: "
                                "check if you have pkgman already running!");
}
void database::unlock_database()
{
    ::unlinkat(fd, "db.lock", 0);
}

void database::load()
{
    for (const auto& entry : std::filesystem::directory_iterator(path))
    {
        if (entry.path().filename().string().starts_with("."))
            continue;

        package
    }
}

database open_database(bool readonly)
{
    std::string path = pkgman::get_sysroot() + "/" + "var/lib/pkgman/db";

    return database{path, readonly};
}
} // namespace backend

} // namespace pkgman
