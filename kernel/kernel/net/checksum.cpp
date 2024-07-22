/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */

#include <stdint.h>

#include <onyx/net/ip.h>

inetsum_t do_checksum(const uint8_t *buf, size_t length)
{
    /* The general algorithm here is to keep aligning the buffer progressively to, 16bit aligned,
     * 32bit aligned, and finally 64bit aligned. Then we have a main loop that adds 64 bytes
     * together, using 'adc'-like instructions(add the registers together + the carry bit). Then, we
     * finally handle trailing portions of the buffer(by testing 32-bit chunks, and then 16-bit
     * chunks, and then handling the trailing byte). This seems to be the standard of doing this in
     * software.
     */

    uint64_t sum = 0;
    if (length == 0) [[unlikely]]
        return 0;

    /* Step 0: Align the buffer to a word boundary(at least).*/
    if (IS_BUFFER_ALIGNED_TO(buf, 1))
    {
        sum = *buf << 8;
        buf++;
        length--;
    }

    /* Right now, nr_blocks represents the number of 16-bit blocks */
    auto nr_blocks = length >> 1;

    if (nr_blocks) [[likely]]
    {
        /* Step 1: Align to a dword boundary if we're not already */
        if (IS_BUFFER_ALIGNED_TO(buf, 2))
        {
            sum += *(may_alias_uint16_t *) buf;
            buf += 2;
            length -= 2;
            nr_blocks--;
        }

        /* Now, we switched to a block_size of 32 bits(4 bytes) */
        nr_blocks >>= 1;

        if (nr_blocks)
        {
            if (IS_BUFFER_ALIGNED_TO(buf, 4))
            {
                sum += *(may_alias_uint32_t *) buf;
                buf += 4;
                length -= 4;
                nr_blocks--;
            }

            /* We're certainly 8-byte aligned right now, so we're going to
             * switch the block size to 64 bytes and enter the main loop.
             */

            /* Note that we save the number of 8 byte blocks for later */
            auto nr_8b_blocks = nr_blocks >> 1;
            nr_blocks >>= 4;

            while (nr_blocks)
            {
                ADD_CARRY_64_BYTES(buf, sum);
                buf += 64;
                nr_blocks--;
            }

            /* Handle leftover 8-byte blocks */
            nr_8b_blocks %= 8;
            while (nr_8b_blocks)
            {
                ADD_CARRY_64BIT(buf, sum);
                nr_8b_blocks--;
                buf += 8;
            }

            /* Now we're going to start wrapping up. */
            /* Note that we fold the 64-bit sum to 32-bits because then we're
             * guaranteed that adding a 32-bit integer + a 16-bit integer + 8-bit integer
             * will not overflow the 64-bit integer, and because of that we won't need to
             * use add-carry instructions anymore.
             */

            sum = addcarry32(sum & 0xffffffff, sum >> 32);

            if (length & 4)
            {
                sum += *(may_alias_uint32_t *) buf;
                buf += 4;
            }
        }

        if (length & 2)
        {
            sum += *(may_alias_uint16_t *) buf;
            buf += 2;
        }
    }

    if (length & 1)
    {
        sum += *buf;
    }

    sum = addcarry32(sum >> 32, sum & 0xffffffff);

    return sum;
}
