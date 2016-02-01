# Boot stages

## First steps
	The bootloader (Grub 2 by default) calls the kernel entry point **loader()**.**loader()** makes the paging structures needed to jump to higher half and enable paging.After that loader() calls **_start()**.
	_start() sets up the stack, adds the KERNEL_VIRTUAL_BASE to the multiboot info structure address and pushes the structure and the magic number.By last, it calls **kernel_early()**.
## kernel_early()
	**kernel_early()**'s function is checking runtime information ( magic number and multiboot ) and initializing architecture dependent features (such as sse and gdt ).**kernel_early()** calls init_arch(), that is hooked by the architecture.**kernel_early()** also initializes the terminal.
## Semi-stable state
	After **kernel_early()** returns, **_start()** calls **_init()**( Basically it initializes the global constructors ). After that, it calls **kernel_main()**, which initializes some less crucial parts of the kernel ( although still very important ). After that, it initializes the task scheduler and jumps to the stable kernel state.
## Stable kernel state
	When the stable kernel state is initiated, everything should be initialzed, and the kernel should have the harddisk mounted ( or the initrd ). It then enters userspace.

# NOTE
	Although everything is nicely documented here, alot of features are still missing from the kernel, and will be added in the near future.