ENTRY(EntryPoint)

VIRT_BASE = 0xffffffff80000000;

SECTIONS
{
	.multiboot : ALIGN(4k)
	{
		*(.multiboot)
	}
	. = 0x100000;
	kernel_start = VIRT_BASE + .;
	_text_start = . + VIRT_BASE;
	.boot :
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
	}

	. += VIRT_BASE;
	.text ALIGN(0x1000) : AT(ADDR(.text) - VIRT_BASE)
	{
		*(.text)
		*(.gnu.linkonce.t*)
		*(.init)
		*(.fini)
		*(.jcr)
		*(.dtors)
		*(.ctors)
	}
	
	.rodata ALIGN(0x1000) : AT(ADDR(.rodata) - VIRT_BASE)
	{
		*(.rodata*)
		*(.gnu.linkonce.r*)
		_driver_init_start = .;
		*(.driver.init*)
		_driver_init_end = .;
	}
	. = ALIGN(0x1000);

	_text_end = .;
	_data_start = .;
	.data ALIGN(0x1000) : AT(ADDR(.data) - VIRT_BASE)
	{
		*(.data)
		*(.gnu.linkonce.d*)
	}

	.bss ALIGN(0x1000) : AT(ADDR(.bss) - VIRT_BASE)
	{
		*(COMMON)
		*(.bss)
		*(.gnu.linkonce.b*)
		. = ALIGN(16);
		*(.bootstrap_stack*)
	}

	. = ALIGN(0x1000);
	_data_end = .;
	_vdso_sect_start = .;
	.vdso ALIGN(0x1000) : AT(ADDR(.vdso) - VIRT_BASE)
	{
		*vdso_helper.o(*.vdso)
	}

	. = ALIGN(0x1000);
	_vdso_sect_end = .;
	kernel_end = .;

}
