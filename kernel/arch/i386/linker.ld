ENTRY(loader)
OUTPUT_FORMAT(elf32-i386)

SECTIONS {
   /* The kernel will live at 3GB + 1MB in the virtual
      address space, which will be mapped to 1MB in the
      physical address space. */
   . = 0x200000;
   .bootstrap :
   {
   *(.bootstrap)
   }
   . = 0xC0100000;

   .text : AT(ADDR(.text) - 0xC0000000) {
	*(.multiboot)       
	*(.text)
	*(.init)
	*(.fini)
	*(.rodata*)
   }

   .data ALIGN (0x1000) : AT(ADDR(.data) - 0xC0000000) {
       *(.data)
   }

   .bss : AT(ADDR(.bss) - 0xC0000000) {
       _sbss = .;
       *(COMMON)
       *(.bss)
       _ebss = .;
   }
   end = .;
}