/*
 * Copyright (c) 2020 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <fstream>
#include <istream>
#include <system_error>

#include <uapi/netkernel.h>

#include <dhcpcd.hpp>
#include <netctl.hpp>

namespace netctl
{

int nkfd;
const std::string config_files_path = "/etc/netctl/";
const char *default_config_path = "/etc/netctl/default-profile.json";

std::vector<std::unique_ptr<instance>> instances;

std::string instance::config_file_path() const
{
    auto last_name_index = name.rfind("/");
    auto last_name = name.substr(last_name_index + 1);

    return config_files_path + last_name + ".json";
}

void instance::create_new_profile(const std::string &cfg)
{
    int default_fd = open(default_config_path, O_RDONLY | O_CLOEXEC);
    if (default_fd < 0)
    {
        throw sys_error("Error opening the default config");
    }

    /* The new profile's perms are 644: Owner RW, Other R, Group R */
    static constexpr unsigned int new_perms = S_IWUSR | S_IRUSR | S_IROTH | S_IRGRP;

    int newfd = open(cfg.c_str(), O_RDWR | O_CREAT | O_TRUNC, new_perms);
    if (newfd < 0)
    {
        close(default_fd);
        throw sys_error("Error creating a new profile " + cfg);
    }

    char buffer[4096];

    ssize_t st = 0;

    while ((st = read(default_fd, buffer, sizeof(buffer))) != 0)
    {
        if (st < 0)
        {
            if (errno == EINTR)
                continue;

            int err = errno;
            close(default_fd);
            unlink(cfg.c_str());
            close(newfd);
            throw sys_error("Error reading from the default fd", err);
        }

        st = write(newfd, buffer, st);

        if (st < 0)
        {
            int err = errno;
            close(default_fd);
            unlink(cfg.c_str());
            close(newfd);
            throw sys_error("Error writing the new profile", err);
        }
    }

    /* Fsync it to make sure it's written, as it's an important config file */

    fsync(newfd);

    close(default_fd);
    close(newfd);
}

void create_instance(const std::string &name)
{
    int fd = open(name.c_str(), O_RDWR);
    if (fd < 0)
    {
        auto error = strerror(errno);

        throw std::runtime_error("Failed to open " + name + ": " + error);
    }

    auto inst = std::make_unique<instance>(fd, name);

    instances.push_back(std::move(inst));
}

} // namespace netctl

int main(int argc, char **argv, char **envp)
{
    // Weird argv.
    if (argc == 0)
        return 1;
    (void) envp;
    int logfd = open("/dev/null", O_RDWR);
    if (logfd < 0)
    {
        perror("could not create logfd");
        return 1;
    }

#if 0
	dup2(logfd, 0);
	dup2(logfd, 1);
	dup2(logfd, 2);
#endif

    close(logfd);

    netctl::nkfd = socket(AF_NETKERNEL, SOCK_DGRAM, 0);
    if (netctl::nkfd < 0)
    {
        perror("nksocket");
        return 1;
    }

    dhcpcd::rtfd = socket(AF_NETKERNEL, SOCK_DGRAM, 0);
    if (dhcpcd::rtfd < 0)
    {
        perror("nksocket");
        return 1;
    }

    sockaddr_nk nksa;
    nksa.nk_family = AF_NETKERNEL;
    strcpy(nksa.path, "ipv4.rt");
    if (connect(dhcpcd::rtfd, (const sockaddr *) &nksa, sizeof(nksa)) < 0)
    {
        perror("nkconnect");
        return 1;
    }

    printf("%s: Daemon initialized\n", argv[0]);

    /* TODO: Discover NICs in /dev (maybe using netlink? or sysfs) */

    std::string name{"/dev/eth0"};
    dhcpcd::init_entropy();

    netctl::create_instance(name);

    while (1)
        sleep(100000);
    return 0;
}
