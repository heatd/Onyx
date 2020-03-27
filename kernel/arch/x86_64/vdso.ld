SECTIONS
{
	. = 0x0;
	.text : ALIGN(0x1000)
	{
		*(.text*)
		*(.gnu.linkonce.t*)
	}

	.data : ALIGN(0x1000)
	{
		*(.data)
		*(.gnu.linkonce.d*)
	}

	.rodata : ALIGN(0x1000)
	{
		*(.rodata*)
		*(.gnu.linkonce.r*)
	}
	
	.bss : ALIGN(0x1000)
	{
		*(COMMON)
		*(.bss)
		*(.gnu.linkonce.b*)
	}
}
