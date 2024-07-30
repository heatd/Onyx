/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#pragma once

#include <optional>
#include <string>
#include <thread>

class Logger
{
private:
    std::string log_filename_;
    std::optional<std::thread> tee_thread{};
    int tee_fd{-1};
    int log_fd{-1};
    int out_fd{-1};
    void DoTee();
    void TeeEntry();

public:
    Logger();
    ~Logger();

    void RedirectOutStreams();
};
