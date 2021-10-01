/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_CMDLINE_H
#define _ONYX_CMDLINE_H

#include <ctype.h>
#include <onyx/expected.hpp>
#include <onyx/fnv.h>
#include <onyx/list.h>
#include <onyx/string_parsing.h>
#include <type_traits>

#define COMMAND_LINE_LENGTH 1024

/**
 * @brief Set the kernel's command line.
 * Should be used by boot protocol code.
 *
 * @param cmdl Pointer to a null terminated kernel command line string.
 *             This string should only contain arguments.
 */
void set_kernel_cmdline(const char *cmdl);

namespace kparam
{
/**
 * @brief Represents a virtual base kernel_param
 *
 */
class kernel_param
{
    const char *name_;
    list_head_cpp<kernel_param> registered_list_node;

public:
    /**
     * @brief Construct a new kernel param object
     *
     * @param name The parameter's name (i.e "acpi.enabled")
     */
    explicit kernel_param(const char *name) : name_{name}, registered_list_node{this}
    {
    }

    /**
     * @brief Handles the parameter's value.
     *
     * @param value Null terminated string of the parameter's value (the
     *              text after '='). If there is no =, value is an empty
     *              string ("").
     * @return True if the value is valid, false if it's not.
     */
    virtual bool handle(const char *value) = 0;

    /**
     * @brief Hashes a kernel parameter.
     *        The current implementation does a simple FNV hash on the name.
     *
     * @param t Kernel parameter to be hashed.
     * @return The FNV-1a hash.
     */
    static fnv_hash_t hash_kparam(kernel_param &t)
    {
        return fnv_hash(t.name_, strlen(t.name_));
    }

    /**
     * @brief Gets a pointer to the registered list node.
     *
     * @return A pointer to the list node.
     */
    list_head *get_registered_list_node()
    {
        return &registered_list_node;
    }
};

template <typename Type>
class typed_kernel_param : public kernel_param
{
    Type value_;

public:
    explicit typed_kernel_param(const char *name) : kernel_param{name}
    {
    }

    /**
     * @brief Set the value of the parameter.
     *
     * @param v Value to set.
     * @return Reference to this.
     */
    typed_kernel_param<Type> &operator=(const Type &v)
    {
        value_ = v;
        return *this;
    }

    /**
     * @brief Convert typed_kernel_param to a <Type>.
     *
     * @return The value of the parameter.
     */
    operator Type() const
    {
        return value_;
    }

    /**
     * @brief Handles the bool parameter's value.
     *
     * @param value Null terminated string of the parameter's value (the
     *              text after '='). If there is no =, value is an empty
     *              string ("").
     * @return True if the value is valid, false if it's not.
     */
    bool handle_bool(const char *value)
    {
        auto ex = parser::parse_bool_from_string(value);

        if (ex.has_error())
            return false;

        value_ = ex.value();
        return true;
    }

    /**
     * @brief Handles the number parameter's value.
     *
     * @param value Null terminated string of the parameter's value (the
     *              text after '='). If there is no =, value is an empty
     *              string ("").
     * @return True if the value is valid, false if it's not.
     */
    bool handle_numeric(const char *value)
    {
        auto ex = parser::parse_number_from_string<Type>(value);

        if (ex.has_error())
            return false;

        value_ = ex.value();
        return true;
    }

    /**
     * @brief Handles the string parameter's value.
     *
     * @param value Null terminated string of the parameter's value (the
     *              text after '='). If there is no =, value is an empty
     *              string ("").
     * @return True if the value is valid, false if it's not.
     */
    bool handle_string(const char *value)
    {
        auto new_val = strdup(value);

        if (!new_val)
        {
            return false;
        }

        value_ = new_val;
        return true;
    }

    /**
     * @brief Handles the parameter's value.
     *
     * @param value Null terminated string of the parameter's value (the
     *              text after '='). If there is no =, value is an empty
     *              string ("").
     * @return True if the value is valid, false if it's not.
     */
    bool handle(const char *value) override
    {
        if constexpr (std::is_same_v<Type, bool>)
        {
            return handle_bool(value);
        }
        else if constexpr (std::is_integral_v<Type>)
        {
            return handle_numeric(value);
        }
        else if constexpr (std::is_same_v<Type, const char *> || std::is_same_v<Type, char *>)
        {
            return handle_string(value);
        }
    }
};
} // namespace kparam

namespace cmdline
{

/**
 * @brief Handle parameters.
 *
 */
void init();

} // namespace cmdline

#define KERNEL_PARAM(name, var_name, type)    \
    kparam::typed_kernel_param<type> var_name \
    {                                         \
        name                                  \
    }

#endif
