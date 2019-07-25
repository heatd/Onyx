ENTRY(entry_point)

VIRT_BASE = 0xffffffff80000000;
PHYS_BASE = 0x100000;

PHDRS
{
	boot PT_LOAD FLAGS(7);
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
		. += 0x8000;
	} : boot

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
	} : text

	_ro_end = .;
	. = ALIGN(0x1000);

	_text_end = .;
	_data_start = .;
	.data ALIGN(0x1000) : AT(ADDR(.data) - VIRT_BASE)
	{
		*(.data)
		__percpu_start = .;
		*(.percpu*)
		__percpu_end = .;
		*(.gnu.linkonce.d*)
	} : data

	.bss ALIGN(0x1000) : AT(ADDR(.bss) - VIRT_BASE)
	{
		*(COMMON)
		*(.bss)
		*(.gnu.linkonce.b*)
		. = ALIGN(16);
		*(.bootstrap_stack*)
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
