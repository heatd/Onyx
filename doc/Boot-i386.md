# Boot stages

## First steps
The bootloader (Grub 2 by default) calls the kernel entry point `loader()`.`loader()` creates the paging structures needed to jump to higher half and enable paging.After that `loader()` calls `_start()`.
`_start()` sets up the stack, adds the KERNEL_VIRTUAL_BASE to the multiboot info structure address and pushes the structure and the magic number.By last, it calls `kernel_early()`.
## KernelEarly()
`KernelEarly()`'s function is checking runtime information ( magic number and multiboot ) and initializing architecture dependent features (such as sse and gdt ).`KernelEarly()` calls `init_arch()`, that is hooked by the architecture.`KernelEarly()` also initializes the terminal.
## Semi-stable state
After `KernelEarly()` returns, `_start()` calls `_init()`( Basically it initializes the global constructors ). After that, it calls `KernelMain()`, which initializes some less crucial parts of the kernel ( although still very important ). After that, it initializes the task scheduler and jumps to the stable kernel state.
## Stable kernel state
When the stable kernel state is initiated, everything should be initialzed, and the kernel should have the harddisk mounted ( or the initrd ). It then enters userspace.
