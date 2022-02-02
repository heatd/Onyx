/*
 * Copyright (c) 2018 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#define _BSD_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <string.h>
#include <sys/dir.h>
#include <sys/stat.h>
#include <unistd.h>

#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

class Device
{
private:
    std::string name;
    std::mutex mtx;
    std::unique_ptr<int> j;

public:
    Device(std::string name) : name(name)
    {
    }
    ~Device()
    {
    }
};

namespace DeviceManager
{

std::vector<Device *> device_list;

int Enumerate(int fd)
{
    int dir = openat(fd, "devices", O_RDONLY | O_DIRECTORY);
    if (dir < 0)
    {
        perror("openat");
        return -1;
    }

    DIR *nd = fdopendir(dir);
    if (!nd)
    {
        perror("Error opening dir\n");
        return -1;
    }

    struct dirent *d;
    while ((d = readdir(nd)) != NULL)
    {
        Device *dev = new Device(std::string(d->d_name));

        device_list.push_back(dev);
    }

    return 0;
}

}; // namespace DeviceManager

int main(int argc, char **argv, char **envp)
{
    close(0);
    close(1);
    close(2);
    struct stat buf;
    int fd = open("/sys", O_RDONLY | O_DIRECTORY);
    if (fd < 0)
    {
        perror("Could not open /sys");
        return 1;
    }

    if (fstat(fd, &buf) < 0)
    {
        perror("fstat");
        return 1;
    }

    DIR *dir = fdopendir(fd);

    if (!dir)
    {
        perror("Could not open /sys");
        return 1;
    }

    struct dirent *d;
    while ((d = readdir(dir)) != NULL)
    {
        if (d->d_type == DT_DIR)
        {
            if (!strcmp(d->d_name, "devices"))
            {
                if (DeviceManager::Enumerate(fd) < 0)
                    return 1;
            }
        }
    }

    while (1)
        sleep(10000);
}
