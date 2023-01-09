/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_CRC32_H
#define _ONYX_CRC32_H

#include <stddef.h>
#include <stdint.h>

uint32_t crc32_calculate(const uint8_t *ptr, size_t len);

/**
   Calculates the CRC32c checksum of the given buffer.
   @param[in]      buffer        Pointer to the buffer.
   @param[in]      length        Length of the buffer, in bytes.
   @param[in]      initial_value Initial value of the CRC.
   @return The CRC32c checksum.
**/
uint32_t crc32c_calculate(const void *buffer, size_t length, uint32_t initial_value);

/**
   Calculates the CRC16-ANSI checksum of the given buffer.

   @param[in]      Buffer        Pointer to the buffer.
   @param[in]      Length        Length of the buffer, in bytes.
   @param[in]      InitialValue  Initial value of the CRC.

   @return The CRC16-ANSI checksum.
**/
uint16_t crc16_calculate(const void *Buffer, size_t Length, uint16_t InitialValue);

#endif
