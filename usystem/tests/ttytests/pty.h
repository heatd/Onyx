// SPDX-License-Identifier: GPL-2.0-only
#ifndef PTY_H
#define PTY_H

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <stdexcept>
#include <string>

class pty_pair
{
public:
    int ptm_fd, pts_fd;
    pty_pair()
    {
        ptm_fd = posix_openpt(O_RDWR | O_NOCTTY);
        if (ptm_fd < 0)
            throw std::runtime_error(std::string("posix_openpt failed: ") + strerror(errno));
        const char *slave_name = ptsname(ptm_fd);
        if (!slave_name)
            throw std::runtime_error(std::string("ptsname failed: ") + strerror(errno));
        if (unlockpt(ptm_fd) < 0)
            throw std::runtime_error(std::string("unlockpt failed: ") + strerror(errno));
        if (grantpt(ptm_fd) < 0)
            throw std::runtime_error(std::string("grantpt failed: ") + strerror(errno));
        pts_fd = open(slave_name, O_RDWR | O_NOCTTY | O_CLOEXEC);
        if (pts_fd < 0)
            throw std::runtime_error(std::string("open failed: ") + slave_name + ": " +
                                     strerror(errno));
    }

    ~pty_pair()
    {
        close(ptm_fd);
        close(pts_fd);
    }

    void reopen_pty_with_ctty()
    {
        const char *slave_name = ptsname(ptm_fd);
        if (!slave_name)
            throw std::runtime_error(std::string("ptsname failed: ") + strerror(errno));
        // close(pts_fd);
        int old = pts_fd;
        pts_fd = open(slave_name, O_RDWR | O_CLOEXEC);
        if (pts_fd < 0)
            throw std::runtime_error(std::string("open failed: ") + slave_name + ": " +
                                     strerror(errno));
        close(old);
    }
};

#endif
