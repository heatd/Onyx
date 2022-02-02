/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#include <fcntl.h>
#include <logging.h>
#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <stdexcept>
#include <string_view>
#include <system_error>

using namespace std::literals::string_view_literals;
using namespace std::literals::string_literals;

static constexpr bool tee_stdout = true;

void CreateLogDirs()
{
    static std::string_view paths[] = {"/var"sv, "/var/log"sv, "/var/log/coredumpd"sv};

    for (const auto &p : paths)
    {
        struct stat buf;
        if (stat(p.data(), &buf) < 0)
        {
            if (errno != ENOENT)
                throw std::system_error(errno, std::generic_category(),
                                        "Failed to stat "s + p.data());

            if (mkdir(p.data(), 0644) < 0)
                throw std::system_error(errno, std::generic_category(),
                                        "Failed to create log directory "s + p.data());
        }
    }
}

Logger::Logger() : log_filename_{"/var/log/coredumpd/"}
{
    CreateLogDirs();

    /* Let's generate an ISO8601 formatted timestamp to help us generate a unique log file name */
    auto end = std::chrono::system_clock::now();

    auto epoch = std::chrono::system_clock::to_time_t(end);
    auto date = gmtime(&epoch);

    // TODO: Pad dates with two digits
    log_filename_ += "coredump-" + std::to_string(date->tm_year) + "-" +
                     std::to_string(date->tm_mon) + "-" + std::to_string(date->tm_mday) + "T" +
                     std::to_string(date->tm_hour) + ":" + std::to_string(date->tm_min) + ":" +
                     std::to_string(date->tm_sec) + ".log";

    int fd = open(log_filename_.c_str(), O_CREAT | O_RDWR);
    if (fd < 0)
        throw std::system_error(errno, std::generic_category(),
                                "Failed to create log file "s + log_filename_);

    log_fd = fd;
}

Logger::~Logger()
{
    // TODO: Add thread exit?
    if (tee_thread.has_value())
    {
        tee_thread.value().join();
        close(tee_fd);
    }

    fsync(log_fd);
    close(log_fd);
}

void Logger::RedirectOutStreams()
{
    if (!tee_stdout)
    {
        /* Quick and old reliable dup2 */
        if (dup2(log_fd, STDOUT_FILENO) < 0 || dup2(log_fd, STDERR_FILENO) < 0)
            throw std::system_error(errno, std::generic_category(), "dup2 error");
    }
    else
    {
        DoTee();
    }
}

void Logger::DoTee()
{
    /* Setup a tee(1) like behaviour by creating a pipe and pointing std(out, err) at it.
     * A thread of ours will then keep blocking on the read end and writing to both
     * the log file and regular stdout.
     */

    int pipefd[2];

    if (pipe(pipefd) < 0)
        throw std::system_error(errno, std::generic_category(), "pipe error");

    if ((out_fd = dup(STDOUT_FILENO)) < 0)
        throw std::system_error(errno, std::generic_category(), "dup error");

    if (dup2(pipefd[1], STDOUT_FILENO) < 0 || dup2(pipefd[1], STDERR_FILENO) < 0)
        throw std::system_error(errno, std::generic_category(), "dup2 error");

    // We can close the write end since we already dup'd it
    close(pipefd[1]);

    // We'll need the read end for later, though
    tee_fd = pipefd[0];

    tee_thread = std::thread{&Logger::TeeEntry, this};
}

void Logger::TeeEntry()
{
    char buffer[8192];
    ssize_t st;

    // TODO: Signals shouldn't be an issue here right?
    while ((st = read(tee_fd, buffer, sizeof(buffer))) > 0)
    {
        if (write(log_fd, buffer, sizeof(buffer)) < 0)
            throw std::system_error(errno, std::generic_category(), "log write error");
        if (write(out_fd, buffer, sizeof(buffer)) < 0)
            throw std::system_error(errno, std::generic_category(), "log write error(stdout)");

        fsync(log_fd);
    }
}
