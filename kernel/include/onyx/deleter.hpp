/*
 * Copyright (c) 2019 Pedro Falcato
 * This file is part of Carbon, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#ifndef _CARBON_DELETER_H
#define _CARBON_DELETER_H

template <typename target_type>
class deleter
{
public:
    virtual void operator()(target_type *ptr) = 0;
};

template <typename target_type>
class default_deleter
{
public:
    virtual void operator()(target_type *ptr) override
    {
        delete ptr;
    }
};

#endif