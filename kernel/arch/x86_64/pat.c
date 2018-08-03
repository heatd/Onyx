/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <onyx/log.h>
#include <onyx/registers.h>
#include <onyx/cpu.h>
#include <onyx/x86/pat.h>
#include <onyx/vm.h>

#define PAT_WB_INDEX		0
#define PAT_WT_INDEX		1
#define PAT_UNCACHED_INDEX	2
#define PAT_UNCACHEABLE_INDEX	3
#define PAT_WC_INDEX		4
#define PAT_WP_INDEX		5

static uint64_t pat_config[PAT_NR_ENTRIES] = {0};

/* The translation table is already setup to a legacy encoding */
static uint64_t translation_table[PAT_NR_ENTRIES] = 
{
	[__VM_CACHE_TYPE_REGULAR] = 0,
	[__VM_CACHE_TYPE_WT] = 1,
	[__VM_CACHE_TYPE_UNCACHED] = 2,
	[__VM_CACHE_TYPE_UNCACHEABLE] = 3,
	[__VM_CACHE_TYPE_WC] = 0,
	[__VM_CACHE_TYPE_WP] = 0
};

static void update_translation_table(void)
{
	translation_table[__VM_CACHE_TYPE_REGULAR] = PAT_WB_INDEX;
	translation_table[__VM_CACHE_TYPE_WT] = PAT_WT_INDEX;
	translation_table[__VM_CACHE_TYPE_UNCACHED] = PAT_UNCACHED_INDEX;
	translation_table[__VM_CACHE_TYPE_WC] = PAT_WC_INDEX;
	translation_table[__VM_CACHE_TYPE_UNCACHEABLE] = PAT_UNCACHEABLE_INDEX;
	translation_table[__VM_CACHE_TYPE_WP] = PAT_WP_INDEX;
}

static void flush_pat(void)
{
	uint64_t data = (pat_config[0] << 0) | (pat_config[1] << 8)
		| (pat_config[2] << 16) | (pat_config[3] << 24)
		| (pat_config[4] << 32) | (pat_config[5] << 40)
		| (pat_config[6] << 48) | (pat_config[7] << 56);

	wrmsr(IA32_MSR_PAT, data & 0xffffffff, data >> 32);
}

uint8_t cache_to_paging_bits(uint8_t type)
{
	return translation_table[type];
}

void pat_init(void)
{
	if(!x86_has_cap(X86_FEATURE_PAT))
		INFO("x86.pat", "cpu does not support PAT; keeping regular config");
	else
	{
		/* The first 4 are , by default, backwards compatible */
		/* NOTE: There's no reason they are, it just is because
		 * why not
		*/
		pat_config[PAT_WB_INDEX] = PAT_WB;
		pat_config[PAT_WT_INDEX] = PAT_WT;
		pat_config[PAT_UNCACHED_INDEX] = PAT_UNCACHED;
		pat_config[PAT_UNCACHEABLE_INDEX] = PAT_UNCACHEABLE;

		/* Add these two as well */
		pat_config[PAT_WC_INDEX] = PAT_WC;
		pat_config[PAT_WP_INDEX] = PAT_WP;

		update_translation_table();

		flush_pat();
	}
}