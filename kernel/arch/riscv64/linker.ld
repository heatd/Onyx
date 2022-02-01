/*
 * Copyright (c) 2016 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

ENTRY(entry_point)

VIRT_BASE = 0xffffffff00000000;
PHYS_BASE = 0x80080000;

SECTIONS
{
	. = PHYS_BASE;
	kernel_start = VIRT_BASE + .;
	_text_start = . + VIRT_BASE;
	.boot ALIGN(0x1000) :
	{
		*(.boot)
		. = ALIGN(4096);
		boot_page_tables = .;
		. += 0x8000;
	} : boot

	. = ADDR(.boot) + SIZEOF(.boot) + VIRT_BASE;

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
	.sdata ALIGN(0x1000) : AT(ADDR(.sdata) - VIRT_BASE)
	{
		__global_pointer$ = . + 0x800;
		*(.srodata.cst16) *(.srodata.cst8) *(.srodata.cst4) *(.srodata.cst2) *(.srodata .srodata.*)
		*(.sdata .sdata.* .gnu.linkonce.s.*)
	} : data

	.data ALIGN(0x1000) : AT(ADDR(.data) - VIRT_BASE)
	{
		*(.data*)
		*(.gnu.linkonce.d*)
	} : data

	.bss : AT(ADDR(.bss) - VIRT_BASE)
	{
		*(COMMON*)
		*(.bss*)
		*(.gnu.linkonce.b*)
	} : data

	. = ALIGN(0x1000);

	percpu_base = .;

	.percpu 0 : AT(percpu_base - VIRT_BASE)
	{
		__percpu_start = .;
		*(.percpu.abi*)
		*(.percpu*)
		__percpu_end = .;
	} : percpu

	. = ABSOLUTE(percpu_base) + SIZEOF(.percpu);

	. = ALIGN(0x1000);
	_data_end = .;
	_vdso_sect_start = .;
	.vdso : AT(ADDR(.vdso) - VIRT_BASE)
	{
		*vdso_helper.o(*.vdso)
	} : vdso

	. = ALIGN(0x1000);
	_vdso_sect_end = .;
	kernel_end = .;
	PROVIDE_HIDDEN(_start_smp = .);
	PROVIDE_HIDDEN(_end_smp = .);
	PROVIDE_HIDDEN(__kernel_size = kernel_end - kernel_start);
}

PHDRS
{
	boot PT_LOAD FLAGS(5);
	text PT_LOAD FLAGS(5);
	rodata PT_LOAD FLAGS(4);
	eh_frame PT_LOAD FLAGS(4);
	data PT_LOAD FLAGS(6);
	percpu PT_LOAD FLAGS(6);
	vdso PT_LOAD FLAGS(7);
	note PT_NOTE FLAGS(0);
}
