/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>

#include <onyx/panic.h>
#include <onyx/riscv/sbi.h>

extern "C" int do_machine_reboot(unsigned int flags)
{
    auto error = sbi_system_reset(SBI_SYSTEM_RESET_TYPE_COLD_REBOOT, SBI_SYSTEM_RESET_REASON_NONE);

    panic("Failed to reboot: SBI error: %s", sbi_strerror(error));
}

extern "C" int do_machine_shutdown(unsigned int flags)
{
    auto error = sbi_system_reset(SBI_SYSTEM_RESET_TYPE_SHUTDOWN, SBI_SYSTEM_RESET_REASON_NONE);

    panic("Failed to shutdown: SBI error: %s", sbi_strerror(error));
}

extern "C" int do_machine_halt(unsigned int flags)
{
    halt();
    return 0;
}

extern "C" int do_machine_suspend(unsigned int flags)
{
    return -EIO;
}
