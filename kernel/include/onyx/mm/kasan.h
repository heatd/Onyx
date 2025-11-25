/*
 * Copyright (c) 2019 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _MM_KASAN_H
#define _MM_KASAN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <onyx/compiler.h>

__BEGIN_CDECLS

void kasan_init();
void kasan_page_alloc_init();
int kasan_alloc_shadow(unsigned long addr, size_t size, bool accessible);

void kasan_set_state(unsigned long *ptr, size_t size, int state);
void asan_unpoison_shadow(unsigned long addr, size_t size);
void asan_poison_shadow(unsigned long addr, size_t size, uint8_t value);

/**
 * @brief Flush the KASAN memory quarantine
 *
 */

void kasan_flush_quarantine();

/**
 * @brief Add a chunk to the KASAN quarantine
 * Note that the quarantine is careful enough not to overwrite
 * bufctl's flags. This makes normal double-free detection still work.
 *
 * @param ptr Pointer to the chunk
 * @param chunk_size Size of the chunk, in bytes
 */
void kasan_quarantine_add_chunk(void *ptr, size_t chunk_size);

struct page;

/**
 * @brief Add a single struct page to the quarantine
 *
 * @param page Page to add
 */
void kasan_quarantine_add_page(struct page *page);

/**
 * @brief Get the redzone's size for the objsize
 *
 * @param objsize Object size
 * @return Redzone's size, on each side of the object
 */
size_t kasan_get_redzone_size(size_t objsize);

#define KASAN_ACCESSIBLE   0x0
#define KASAN_REDZONE      0xff
#define KASAN_FREED        0xfe
#define KASAN_QUARANTINED  0x9e
#define KASAN_LEFT_REDZONE 0xfa

#ifdef CONFIG_KASAN
struct rcu_head;
void kasan_record_kfree_rcu(struct rcu_head *head, size_t off);
#else
#define kasan_record_kfree_rcu(head, off)
#endif

__END_CDECLS
#endif
