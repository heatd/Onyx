/*
 * Copyright (c) 2019 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_X86_KVM_H
#define _ONYX_X86_KVM_H

#include <stdint.h>

/* Maximum leaf is in eax, KVMKVMKVM is in ebx-ecx-edx */
#define KVM_CPUID_SIGNATURE		0x40000000

#define KVM_CPUID_SIGNATURE_EBX 0x4b4d564b
#define KVM_CPUID_SIGNATURE_ECX 0x564b4d56
#define KVM_CPUID_SIGNATURE_EDX 0x4d

#define KVM_CPUID_FEATURES		0x40000001

/* EAX bits */
#define KVM_FEATURE_CLOCKSOURCE		(1 << 0)
#define KVM_FEATURE_CLOCKSOURCE2	(1 << 3)

#define MSR_KVM_WALL_CLOCK_NEW		0x4b564d00
#define MSR_KVM_SYSTEM_TIME_NEW		0x4b564d01
#define MSR_KVM_WALL_CLOCK		0x11
#define MSR_KVM_SYSTEM_TIME		0x12

/* 4 byte alignment */
struct pvclock_wall_clock
{
	uint32_t version;
	uint32_t sec;
	uint32_t nsec;
} __attribute__((packed));

/* 4 byte alignment */
struct pvclock_system_time
{
	uint32_t version;
	uint32_t pad0;
	uint64_t tsc_timestamp;
	uint64_t system_time;
	uint32_t tsc_to_system_mul;
	int8_t tsc_shift;
	uint8_t flags;
	uint8_t pad[2];
} __attribute__((packed));

#define MSR_KVM_SYSTEM_TIME_ENABLE	(1 << 0)

void kvm_init(void);

#endif
