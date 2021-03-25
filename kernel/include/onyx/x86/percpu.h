/*
* Copyright (c) 2021 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_X86_PERCPU_H
#define _ONYX_X86_PERCPU_H

#define get_per_cpu(var) 			\
({						\
	unsigned long val;			\
	__asm__ __volatile__("movq %%gs:" 	\
	"%p1, %0" : "=r"(val) : "i"(&var)); 	\
	(__typeof__(var)) val;			\
})

#define get_per_cpu_no_cast(var) 		\
({						\
	unsigned long val;			\
	__asm__ __volatile__("movq %%gs:" 	\
	"%p1, %0" : "=r"(val) : "i"(&var)); 	\
	val;					\
})

#define write_per_cpu_1(var, val) 		\
({						\
	__asm__ __volatile__("movb %0, %%gs:"   \
	"%p1":: "r"(((uint8_t) (unsigned long) val)), "i"(&var)); \
})

#define write_per_cpu_2(var, val) 		\
({						\
	__asm__ __volatile__("movw %0, %%gs:"   \
	"%p1":: "r"(val), "i"(&var)); 		\
})

#define write_per_cpu_4(var, val) 		\
({						\
	__asm__ __volatile__("movl %0, %%gs:"   \
	"%p1":: "r"(val), "i"(&var)); 		\
})

#define write_per_cpu_8(var, val) 		\
({						\
	__asm__ __volatile__("movq %0, %%gs:"   \
	"%p1":: "r"((unsigned long) val), "i"(&var)); 		\
})

#define add_per_cpu_1(var, val) 		\
({						\
	__asm__ __volatile__("addb %0, %%gs:"   \
	"%p1":: "r"(val), "i"(&var)); 		\
})

#define add_per_cpu_2(var, val) 		\
({						\
	__asm__ __volatile__("addw %0, %%gs:"   \
	"%p1":: "r"(val), "i"(&var)); 		\
})

#define add_per_cpu_4(var, val) 		\
({						\
	__asm__ __volatile__("addl %0, %%gs:"   \
	"%p1":: "r"(val), "i"(&var)); 		\
})

#define add_per_cpu_8(var, val) 		\
({						\
	__asm__ __volatile__("addq %0, %%gs:"   \
	"%p1":: "r"((unsigned long) val), "i"(&var)); 		\
})

#endif
