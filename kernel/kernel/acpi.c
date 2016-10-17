/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <acpi.h>
#include <stdio.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include <kernel/compiler.h>
#include <kernel/vmm.h>
#include <kernel/panic.h>
extern uintptr_t rsdp;
static const ACPI_EXCEPTION_INFO    AcpiGbl_ExceptionNames_Env[] =
{
    EXCEP_TXT ((char*)"AE_OK",                         (char*)"No error"),
    EXCEP_TXT ((char*)"AE_ERROR",                      (char*)"Unspecified error"),
    EXCEP_TXT ((char*)"AE_NO_ACPI_TABLES",             (char*)"ACPI tables could not be found"),
    EXCEP_TXT ((char*)"AE_NO_NAMESPACE",               (char*)"A namespace has not been loaded"),
    EXCEP_TXT ((char*)"AE_NO_MEMORY",                  (char*)"Insufficient dynamic memory"),
    EXCEP_TXT ((char*)"AE_NOT_FOUND",                 (char*) "A requested entity is not found"),
    EXCEP_TXT ((char*)"AE_NOT_EXIST",                  (char*)"A required entity does not exist"),
    EXCEP_TXT ((char*)"AE_ALREADY_EXISTS",             (char*)"An entity already exists"),
    EXCEP_TXT ((char*)"AE_TYPE",                       (char*)"The object type is incorrect"),
    EXCEP_TXT ((char*)"AE_NULL_OBJECT",               (char*) "A required object was missing"),
    EXCEP_TXT ((char*)"AE_NULL_ENTRY",                 (char*)"The requested object does not exist"),
    EXCEP_TXT ((char*)"AE_BUFFER_OVERFLOW",            (char*)"The buffer provided is too small"),
    EXCEP_TXT ((char*)"AE_STACK_OVERFLOW",             (char*)"An internal stack overflowed"),
    EXCEP_TXT ((char*)"AE_STACK_UNDERFLOW",            (char*)"An internal stack underflowed"),
    EXCEP_TXT ((char*)"AE_NOT_IMPLEMENTED",            (char*)"The feature is not implemented"),
    EXCEP_TXT ((char*)"AE_SUPPORT",                   (char*) "The feature is not supported"),
    EXCEP_TXT ((char*)"AE_LIMIT",                     (char*) "A predefined limit was exceeded"),
    EXCEP_TXT ((char*)"AE_TIME",                       (char*)"A time limit or timeout expired"),
    EXCEP_TXT ((char*)"AE_ACQUIRE_DEADLOCK",           (char*)"Internal error, attempt was made to acquire a mutex in improper order"),
    EXCEP_TXT ((char*)"AE_RELEASE_DEADLOCK",           (char*)"Internal error, attempt was made to release a mutex in improper order"),
    EXCEP_TXT ((char*)"AE_NOT_ACQUIRED",               (char*)"An attempt to release a mutex or Global Lock without a previous acquire"),
    EXCEP_TXT ((char*)"AE_ALREADY_ACQUIRED",           (char*)"Internal error, attempt was made to acquire a mutex twice"),
    EXCEP_TXT ((char*)"AE_NO_HARDWARE_RESPONSE",       (char*)"Hardware did not respond after an I/O operation"),
    EXCEP_TXT ((char*)"AE_NO_GLOBAL_LOCK",             (char*)"There is no FACS Global Lock"),
    EXCEP_TXT ((char*)"AE_ABORT_METHOD",               (char*)"A control method was aborted"),
    EXCEP_TXT ((char*)"AE_SAME_HANDLER",              (char*) "Attempt was made to install the same handler that is already installed"),
    EXCEP_TXT ((char*)"AE_NO_HANDLER",                (char*) "A handler for the operation is not installed"),
    EXCEP_TXT ((char*)"AE_OWNER_ID_LIMIT",             (char*)"There are no more Owner IDs available for ACPI tables or control methods"),
    EXCEP_TXT ((char*)"AE_NOT_CONFIGURED",             (char*)"The interface is not part of the current subsystem configuration"),
    EXCEP_TXT ((char*)"AE_ACCESS",                     (char*)"Permission denied for the requested operation")
};
uint32_t acpi_shutdown(void *context)
{
	UNUSED_PARAMETER(context);
	AcpiEnterSleepStatePrep(5);
	asm volatile("cli");
	AcpiEnterSleepState(5);
	panic("ACPI: Failed to enter sleep state! Panic'ing!");
	return 0;
}
int acpi_initialize()
{
    ACPI_STATUS st = AcpiInitializeSubsystem();
	if(ACPI_FAILURE(st))
	{
		printf("Error: %s\n", AcpiGbl_ExceptionNames_Env[st].Name);
		panic("ACPI subsystem initialization failed!");
	}	
	st = AcpiInitializeTables(NULL, 32, true);
	if(ACPI_FAILURE(st))
	{
		printf("Error: %s\n %s\n", AcpiGbl_ExceptionNames_Env[st].Name);
		panic("ACPI table subsystem initialization failed!");
	}
	st = AcpiLoadTables();
	if(ACPI_FAILURE(st))
		panic("AcpiLoadTables failed!");
	
	st = AcpiEnableSubsystem (ACPI_FULL_INITIALIZATION);
	if (ACPI_FAILURE (st))
		panic("AcpiEnableSubsystem failed!");
	st = AcpiInitializeObjects (ACPI_FULL_INITIALIZATION);
	if(ACPI_FAILURE(st))
		panic("AcpiInitializeObjects failed!");

	printf("ACPI initialized!\n");

	return 0;
}