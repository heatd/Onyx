ENTRY(_start)

VIRT_BASE = 0xffffffff80000000;
PHYS_BASE = 0x100000;

PHDRS
{
	boot PT_LOAD FLAGS(7);
	percpu PT_LOAD FLAGS(6);
	text PT_LOAD FLAGS(5);
	data PT_LOAD FLAGS(6);
	vdso PT_LOAD FLAGS(7);
}

SECTIONS
{
	. = PHYS_BASE;
	kernel_start = VIRT_BASE + .;
	_text_start = . + VIRT_BASE;
	.boot ALIGN(0x1000) : AT(PHYS_BASE)
	{
		*(.boot)
		. = ALIGN(4096);
		pml4 = .;
		. += 0x1000;
		pdpt = .;
		. += 0x1000;
		pd = .;
		. += 0x1000;
		pdlower = .;
		. += 0x1000;
		pdptphysical_map = .;
		. += 0x1000;
		pml5 = .;
		. += 0x1000;
	} : boot

	percpu_base = .;
	. = 0;

	.percpu : AT(percpu_base)
	{
		__percpu_start = .;
		*(.percpu*)
		__percpu_end = .;
	} : percpu
	
	. += percpu_base;
	. = ALIGN(0x1000);

	. += VIRT_BASE;

	.text ALIGN(0x1000) : AT(ADDR(.text) - VIRT_BASE)
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
	} : text

	_ro_end = .;
	. = ALIGN(0x1000);

	_text_end = .;
	_data_start = .;
	.data ALIGN(0x1000) : AT(ADDR(.data) - VIRT_BASE)
	{
		*(.data*)
		*(.gnu.linkonce.d*)
	} : data

	.bss ALIGN(0x1000) : AT(ADDR(.bss) - VIRT_BASE)
	{
		*(COMMON)
		*(.bss)
		*(.gnu.linkonce.b*)
	} : data

	. = ALIGN(0x1000);
	_data_end = .;
	_vdso_sect_start = .;
	.vdso ALIGN(0x1000) : AT(ADDR(.vdso) - VIRT_BASE)
	{
		*vdso_helper.o(*.vdso)
	} : vdso

	. = ALIGN(0x1000);
	_vdso_sect_end = .;
	kernel_end = .;
}
