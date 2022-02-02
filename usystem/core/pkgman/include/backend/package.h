/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#pragma once

#include <string>

#include <json.hpp>

namespace pkgman
{

namespace backend
{

class database;

class package
{
private:
    std::string name;
    nlohmann::json manifest;

public:
    package();
};

} // namespace backend

} // namespace pkgman
