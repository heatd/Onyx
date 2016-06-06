ENTRY(EntryPoint)

VIRT_BASE = 0xFFFFFFFF80000000;

SECTIONS
{
	.multiboot : ALIGN(4k)
	{
		*(.multiboot)
	}
	. = 0x100000;
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
		. += 0x8000;
	}

	. += VIRT_BASE;
	kernel_start = .;
	.tss ALIGN(0x1000) : AT(ADDR(.tss) - VIRT_BASE)
	{
		tss = .;
		. += 0x1000;
	}
	.text ALIGN(0x1000) : AT(ADDR(.text) - VIRT_BASE)
	{
		*(.text)
		*(.gnu.linkonce.t*)
		*(.bootstrap_stack)
		*(.init)
		*(.fini)
		*(.jcr)
		*(.dtors)
		*(.ctors)
	}

	.data ALIGN(0x1000) : AT(ADDR(.data) - VIRT_BASE)
	{
		*(.data)
		*(.gnu.linkonce.d*)
	}

	.rodata ALIGN(0x1000) : AT(ADDR(.rodata) - VIRT_BASE)
	{
		*(.rodata*)
		*(.gnu.linkonce.r*)
	}

	.bss ALIGN(0x1000) : AT(ADDR(.bss) - VIRT_BASE)
	{
		*(COMMON)
		*(.bss)
		*(.gnu.linkonce.b*)
	}
	kernel_end = .;

}
