/*
 * Copyright (c) 2016 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

ENTRY(entry_point)

VIRT_BASE = 0xffffffff80000000;
PHYS_BASE = 0x1000000;

SECTIONS
{
	. = PHYS_BASE;
	kernel_start = VIRT_BASE + .;
	_text_start = . + VIRT_BASE;
	.boot ALIGN(0x1000) :
	{
		*(.boot)
		*(.boot.data)
		. = ALIGN(4096);
		PROVIDE_HIDDEN(__early_page_tables_start = .);
		pml4 = .;
		. += 0x1000;
		pdpt = .;
		. += 0x1000;
		pd = .;
		. += 0x1000;
		/* Reserve 4 page tables for pdlowers
		 * This will cover the bottom 4GB, which is our current restriction
		 * for load addresses.
		 */
		pdlower = .;
		. += 0x4000;
		pdptphysical_map = .;
		. += 0x1000;
		pml5 = .;
		. += 0x1000;
		PROVIDE_HIDDEN(__early_page_tables_end = .);
		PROVIDE_HIDDEN(__early_page_tables_size = __early_page_tables_end - __early_page_tables_start);
	} : boot

	. += VIRT_BASE;

	.text : AT(ADDR(.text) - VIRT_BASE)
	{
		*(.text*)
		*(.gnu.linkonce.t*)
		*(.init)
		*(.fini)
		*(.jcr)
		*(.dtors)
		*(.ctors)
	} : text
	
	_ro_start = .;

	.rodata ALIGN(0x1000) : AT(ADDR(.rodata) - VIRT_BASE)
	{
		PROVIDE_HIDDEN(__init_array_start = .);
		*(.init_array*)
		PROVIDE_HIDDEN(__init_array_end = .);
		PROVIDE_HIDDEN(__fini_array_start = .);
		*(.fini_array*)
		PROVIDE_HIDDEN(__fini_array_end = .);
		*(.rodata*)
		*(.gnu.linkonce.r*)
		_driver_init_start = .;
		*(.driver.init*)
		_driver_init_end = .;
		_ehtable_start = .;
		*(.ehtable*)
		_ehtable_end = .;
		__mcount_loc_start = .;
		*(__mcount_loc)
		__mcount_loc_end = .;
		__return_loc_start = .;
		*(__return_loc)
		__return_loc_end = .;
		__init_level0_start = .;
		*(.init.level0)
		__init_level0_end = .;
		__init_level1_start = .;
		*(.init.level1)
		__init_level1_end = .;
		__init_level2_start = .;
		*(.init.level2)
		__init_level2_end = .;
		__init_level3_start = .;
		*(.init.level3)
		__init_level3_end = .;
		__init_level4_start = .;
		*(.init.level4)
		__init_level4_end = .;
		__init_level5_start = .;
		*(.init.level5)
		__init_level5_end = .;
		__init_level6_start = .;
		*(.init.level6)
		__init_level6_end = .;
		__init_level7_start = .;
		*(.init.level7)
		__init_level7_end = .;
		__init_level8_start = .;
		*(.init.level8)
		__init_level8_end = .;
		__start_testcases = .;
		*(.testcases*)
		__end_testcases = .;
		__start_code_patch = .;
		*(.code_patch*)
		__end_code_patch = .;
		*(.modinfo*)
		*(.eh_frame_hdr)
		*(.eh_frame)
	} : rodata

	.note.gnu.build-id :
	{
        PROVIDE_HIDDEN(__build_id_note_start = .);
        *(.note.gnu.build-id)
        PROVIDE_HIDDEN(__build_id_note_end = .);
    } :rodata :note

	_ro_end = .;
	. = ALIGN(0x1000);

	_text_end = .;
	_data_start = .;

	percpu_base = .;

	.percpu 0 : AT(percpu_base - VIRT_BASE)
	{
		__percpu_start = .;
		*(.percpu.abi*)
		*(.percpu*)
		__percpu_end = .;
	} : percpu

	. = ABSOLUTE(percpu_base) + SIZEOF(.percpu);

	.data ALIGN(0x1000) : AT(ADDR(.data) - VIRT_BASE)
	{
		*(.data*)
		*(.gnu.linkonce.d*)
	} : data

	. = ALIGN(0x1000);

	_bss_start = .;
	.bss : AT(ADDR(.bss) - VIRT_BASE)
	{
		*(COMMON*)
		*(.bss*)
		*(.gnu.linkonce.b*)
	} : data
	_bss_end = .;
	_bss_size = _bss_end - _bss_start;

	. = ALIGN(0x1000);
	_data_end = .;
	_data_size = _data_end - _data_start;

	__pecoff_data_size = _bss_start - _data_start;

	. = ALIGN(0x1000);
	_vdso_sect_end = .;
	kernel_end = .;
	kernel_phys_end = . - VIRT_BASE;
	PROVIDE_HIDDEN(__kernel_size = kernel_end - kernel_start);
}

PHDRS
{
	boot PT_LOAD FLAGS(5);
	text PT_LOAD FLAGS(5);
	rodata PT_LOAD FLAGS(4);
	eh_frame PT_LOAD FLAGS(4);
	percpu PT_LOAD FLAGS(6);
	data PT_LOAD FLAGS(6);
	note PT_NOTE FLAGS(0);
}
