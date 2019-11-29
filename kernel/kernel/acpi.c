/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <acpi.h>
#include <stdio.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <limits.h>

#include <onyx/mutex.h>
#include <onyx/spinlock.h>
#include <onyx/acpi.h>
#include <onyx/log.h>
#include <onyx/compiler.h>
#include <onyx/vm.h>
#include <onyx/panic.h>
#include <onyx/log.h>
#include <onyx/cpu.h>
#include <onyx/pnp.h>
#include <onyx/dev.h>
#include <onyx/apic.h>
#include <onyx/clock.h>
#include <onyx/platform.h>
#include <fractions.h>

#include <pci/pci.h>

int acpi_init_timer(void);

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
	DISABLE_INTERRUPTS();
	AcpiEnterSleepState(5);

	panic("ACPI: Failed to enter sleep state! Panic'ing!");
	return 0;
}

extern int __enter_sleep_state(uint8_t sleep_state);

unsigned int acpi_suspend(void *context)
{
	UNUSED_PARAMETER(context);
	/* Prepare to enter S3 */
	ACPI_STATUS st = AcpiEnterSleepStatePrep(2);
	if(ACPI_FAILURE(st))
		return 1;
	DISABLE_INTERRUPTS();
	/* We'll need to enter assembly in order to correctly save and restore
	 * registers
	*/
	if(__enter_sleep_state(2) < 0)
		return -1;
	return 0;
}

static ACPI_HANDLE root_bridge;
static ACPI_DEVICE_INFO *root_bridge_info;
int acpi_shutdown_device(struct device *dev);
static struct bus acpi_bus = 
{
	.name = "acpi",
	.shutdown = acpi_shutdown_device
};

ACPI_STATUS acpi_walk_irq(ACPI_HANDLE object, UINT32 nestingLevel,
	void *context, void **returnvalue)
{
	ACPI_DEVICE_INFO *devinfo;
	ACPI_STATUS st = AcpiGetObjectInfo(object, &devinfo);

	if(ACPI_FAILURE(st))
	{
		ERROR("acpi", "Error: AcpiGetObjectInfo failed!\n");
		return AE_ERROR;
	}

	if(devinfo->Flags & ACPI_PCI_ROOT_BRIDGE)
	{
		root_bridge = object;
		root_bridge_info = devinfo;
	}
	else
		free(devinfo);
	return AE_OK;
}

uint32_t acpi_execute_pic(int value)
{
	ACPI_OBJECT arg;
	ACPI_OBJECT_LIST list;

	arg.Type = ACPI_TYPE_INTEGER;
	arg.Integer.Value = value;
	list.Count = 1;
	list.Pointer = &arg;

	return AcpiEvaluateObject(ACPI_ROOT_OBJECT, (char*)"_PIC", &list, NULL);
}

int enumerate_pci_irq_routing(ACPI_PCI_ROUTING_TABLE *table, struct bus *bus,
	ACPI_HANDLE handle)
{
	/* TODO: Refactor and improve this */
	ACPI_PCI_ROUTING_TABLE *it = table;
	for(; it->Length != 0; it = (ACPI_PCI_ROUTING_TABLE*) ACPI_NEXT_RESOURCE(it))
	{
		uint8_t device = it->Address >> 16;
		struct pci_device_address addr = {0};
		addr.device = device;
		struct pci_device *dev = get_pcidev(&addr);
		if(!dev)
			continue;

		uint32_t pin = it->Pin;
		uint32_t gsi = -1;
		bool level = true;
		bool active_high = false;

		if(it->Source[0] == 0)
		{
			gsi = it->SourceIndex;
		}
		else
		{
			ACPI_HANDLE link_obj;
			ACPI_STATUS st = AcpiGetHandle(handle, it->Source,
				&link_obj);

			if(ACPI_FAILURE(st))
			{
				ERROR("acpi", "Error while calling "
				"AcpiGetHandle: %s\n", AcpiGbl_ExceptionNames_Env[st].Name);
				return -1;
			}
			ACPI_BUFFER buf;
			buf.Length = ACPI_ALLOCATE_BUFFER;
			buf.Pointer = NULL;

			st = AcpiGetCurrentResources(link_obj, &buf);
			if(ACPI_FAILURE(st))
			{
				ERROR("acpi", "Error while calling "
				"AcpiGetCurrentResources: %s\n", AcpiGbl_ExceptionNames_Env[st].Name);
				return -1;
			}
			
			for(ACPI_RESOURCE *res = (ACPI_RESOURCE*) buf.Pointer;
				res->Type != ACPI_RESOURCE_TYPE_END_TAG; res =
				ACPI_NEXT_RESOURCE(res))
			{
				if(res->Type == ACPI_RESOURCE_TYPE_IRQ)
				{
					level = res->Data.Irq.Polarity == 0 ? true : false;
					active_high = res->Data.Irq.Triggering == 0 ? true : false;
					gsi = res->Data.Irq.Interrupts[it->SourceIndex];
					break;
				}
				else if(res->Type == ACPI_RESOURCE_TYPE_EXTENDED_IRQ)
				{
					level = res->Data.ExtendedIrq.Polarity == 0 ? true : false;
					active_high = res->Data.ExtendedIrq.Triggering == 0 ? true : false;
					gsi = res->Data.ExtendedIrq.Interrupts[it->SourceIndex];
					break;
				}
			}
			free(buf.Pointer);
		}

		printf("acpi: 00:%02x:00: pin INT%c ==> GSI %u\n", device,
		       'A' + pin, gsi);
		dev->pin_to_gsi[pin].level = level;
		dev->pin_to_gsi[pin].active_high = active_high;
		dev->pin_to_gsi[pin].gsi = gsi;
	}
	return 0;
}


ACPI_STATUS acpi_find_pci_buses(ACPI_HANDLE object, UINT32 nestingLevel,
	void *context, void **returnvalue)
{
	ACPI_DEVICE_INFO *devinfo;
	ACPI_STATUS st = AcpiGetObjectInfo(object, &devinfo);

	if(ACPI_FAILURE(st))
	{
		ERROR("acpi", "Error: AcpiGetObjectInfo failed!\n");
		return AE_ERROR;
	}

	if(devinfo->Flags & ACPI_PCI_ROOT_BRIDGE)
	{
		ACPI_BUFFER buffer = {0};
		buffer.Length = ACPI_ALLOCATE_BUFFER;
		if((st = AcpiGetIrqRoutingTable(object, &buffer)) != AE_OK)
		{
			ERROR("acpi", "Error: AcpiGetIrqRoutingTable failed!\n");
			return st;
		}

		ACPI_PCI_ROUTING_TABLE *rout = buffer.Pointer;
		enumerate_pci_irq_routing(rout, context, object);
		free(rout);
	}

	free(devinfo);
	return AE_OK;
}

int acpi_get_irq_routing_tables(struct bus *bus)
{
	void* retval;
	ACPI_STATUS st = AcpiGetDevices(NULL, acpi_find_pci_buses, bus, &retval);
	if(ACPI_FAILURE(st))
	{
		ERROR("acpi", "Error while calling AcpiGetDevices: %s\n", AcpiGbl_ExceptionNames_Env[st].Name);
		return 1;
	}
	return 0;
}

int acpi_get_irq_routing_info(struct bus *bus)
{
	if(acpi_get_irq_routing_tables(bus))
		return -1;
	return 0;
}

static uintptr_t rsdp = 0;
uintptr_t get_rdsp_from_grub(void);
uint8_t AcpiTbChecksum(uint8_t *buffer, uint32_t len);

void acpi_find_rsdp(void)
{
	if(ACPI_FAILURE(AcpiFindRootPointer(&rsdp)))
	{
		rsdp = get_rdsp_from_grub();
	}
}

uintptr_t acpi_get_rsdp(void)
{
	return rsdp;
}

ACPI_RESOURCE *acpi_get_resource(struct acpi_device *device, uint32_t type,
	unsigned int index)
{
	ACPI_RESOURCE *res = device->resources;

	for(; res->Type != ACPI_RESOURCE_TYPE_END_TAG; res =
		ACPI_NEXT_RESOURCE(res))
	{
		if(res->Type == type && index-- == 0)
			return res;
	}

	return NULL;
}

ACPI_RESOURCE *acpi_get_resources(ACPI_HANDLE object)
{
	ACPI_STATUS st = 0;
	ACPI_BUFFER buf;
	buf.Length = ACPI_ALLOCATE_BUFFER;
	buf.Pointer = NULL;

	if(ACPI_FAILURE((st = AcpiGetCurrentResources(object, &buf))))
	{
		return NULL;
	}

	return buf.Pointer;
}

ACPI_STATUS acpi_add_device(ACPI_HANDLE object, UINT32 nestingLevel, void *context, void **returnvalue)
{
	bool free_id = false;
	ACPI_DEVICE_INFO *info;
	ACPI_STATUS st;
	st = AcpiGetObjectInfo(object, &info);
	if(ACPI_FAILURE(st))
	{
		ERROR("acpi", "AcpiGetObjectInfo() Failed\n");
		return AE_ERROR;
	}

	const char *id = NULL;
	if(info->Valid & ACPI_VALID_HID)
		id = info->HardwareId.String;
	else if (info->Valid & ACPI_VALID_UID)
		id = info->UniqueId.String;
	else if(info->Valid & ACPI_VALID_CID)
		id = info->ClassCode.String;
	else
	{
		ACPI_BUFFER buf;
		buf.Length = ACPI_ALLOCATE_BUFFER;
		buf.Pointer = NULL;

		st = AcpiGetName(object, ACPI_FULL_PATHNAME, &buf);
		if(ACPI_FAILURE(st))
		{
			ERROR("acpi", "AcpiGetName() failed: error %x\n", st);
			return AE_ERROR;
		}
		free_id = true;

		id = buf.Pointer;
	}

	char *name = zalloc(PATH_MAX);
	if(!name)
		return AE_ERROR;

	snprintf(name, PATH_MAX, "%s", id);

	ACPI_RESOURCE *resources = acpi_get_resources(object);

	struct acpi_device *device = malloc(sizeof(struct acpi_device));
	if(!device)
		return AE_ERROR;
	memset(device, 0, sizeof(struct acpi_device));

	device->dev.name = name;
	device->object = object;
	device->info = info;
	device->resources = resources;
	
	bus_add_device(&acpi_bus, (struct device*) device);

	if(free_id)
		free((void*) id);
	return AE_OK;
}

void acpi_enumerate_devices(void)
{
	ACPI_STATUS st;
	/* Walk the namespace for devices */
	st = AcpiWalkNamespace(ACPI_TYPE_DEVICE, ACPI_ROOT_OBJECT,
				    ACPI_UINT32_MAX,
				    acpi_add_device,
				    NULL, NULL, NULL);
	if(ACPI_FAILURE(st))
	{
		ERROR("acpi", "Failed to walk the namespace\n");
	}
}

int acpi_initialize(void)
{
	acpi_find_rsdp();
	ACPI_STATUS st = AcpiInitializeSubsystem();
	if(ACPI_FAILURE(st))
	{
		printk("Error: %s\n", AcpiGbl_ExceptionNames_Env[st].Name);
		panic("ACPI subsystem initialization failed!");
	}

	st = AcpiInitializeTables(NULL, 32, true);
	if(ACPI_FAILURE(st))
	{
		printk("Error: %s\n", AcpiGbl_ExceptionNames_Env[st].Name);
		panic("ACPI table subsystem initialization failed!");
	}

	st = AcpiLoadTables();
	if(ACPI_FAILURE(st))
		panic("AcpiLoadTables failed!");

	ioapic_early_init();
	st = AcpiEnableSubsystem(ACPI_FULL_INITIALIZATION);
	if (ACPI_FAILURE(st))
	{
		printk("Error: %s\n", AcpiGbl_ExceptionNames_Env[st].Name);
		panic("AcpiEnableSubsystem failed!");
	}

	st = AcpiInitializeObjects(ACPI_FULL_INITIALIZATION);
	if(ACPI_FAILURE(st))
		panic("AcpiInitializeObjects failed!");

	INFO("acpi", "initialized!\n");

	/* Register the acpi bus */
	bus_register(&acpi_bus);
	
	/* Enumerate every device */
	acpi_enumerate_devices();

	acpi_init_timer();

	platform_init_acpi();

	return 0;
}

uint32_t acpi_get_apic_id_lapic(ACPI_SUBTABLE_HEADER *madt)
{
	return ((ACPI_MADT_LOCAL_APIC*) madt)->Id;
}

static struct mutex cpu_enum_lock = {0};

static size_t __ndx = 0;

ACPI_STATUS acpi_enumerate_per_cpu(ACPI_HANDLE object, UINT32 nestingLevel, void *context, void **returnvalue)
{
	ACPI_BUFFER buffer = { ACPI_ALLOCATE_BUFFER, NULL};
	struct acpi_processor *processor = &((struct acpi_processor *) context)[__ndx++];
	uint32_t apic_id = (uint32_t) -1;

	/* _MAT returns a segment of the MADT table */
	if(ACPI_FAILURE(AcpiEvaluateObject(object, "_MAT", NULL, &buffer)))
		return AE_ERROR;
	/* Get the APIC ID */
	ACPI_OBJECT *obj = (ACPI_OBJECT*) buffer.Pointer;
	ACPI_SUBTABLE_HEADER *madt_table = (ACPI_SUBTABLE_HEADER *) obj->Buffer.Pointer;
	
	switch(madt_table->Type)
	{
		case ACPI_MADT_TYPE_LOCAL_APIC:
			apic_id = acpi_get_apic_id_lapic(madt_table);
			break;
	}

	processor->object = object;
	processor->apic_id = apic_id;
	ACPI_FREE(buffer.Pointer);
	return AE_OK;
}

struct acpi_processor *acpi_enumerate_cpus(void)
{
	struct acpi_processor *processors = malloc(sizeof(struct acpi_processor) * get_nr_cpus());
	if(!processors)
	{
		return NULL;
	}

	memset(processors, 0, sizeof(struct acpi_processor) * get_nr_cpus());

	mutex_lock(&cpu_enum_lock);

	__ndx = 0;
	/* Walk the namespace, looking for ACPI PROCESSOR objects */
	AcpiWalkNamespace(ACPI_TYPE_PROCESSOR, ACPI_ROOT_OBJECT,
				    ACPI_UINT32_MAX,
				    acpi_enumerate_per_cpu,
				    NULL, processors, NULL);

	mutex_unlock(&cpu_enum_lock);
	return processors;
}

struct acpi_device *acpi_get_device(const char *id)
{
	return (struct acpi_device*) bus_find_device(&acpi_bus, id);
}

char *power_states[] =
{
	"_PS0",
	"_PS1",
	"_PS2",
	"_PS3"
};

int acpi_set_device_power_state(struct acpi_device *device, unsigned int power_state)
{
	ACPI_STATUS st = AcpiEvaluateObject(device->object, power_states[power_state], NULL, NULL);
	if(ACPI_FAILURE(st))
	{
		return 1;
	}

	return 0;
}

int acpi_shutdown_device(struct device *dev)
{
	assert(dev);
	return acpi_set_device_power_state((struct acpi_device *) dev, ACPI_POWER_STATE_D3);
}

uint64_t acpi_timer_get_ticks(void);
hrtime_t acpi_timer_get_elapsed_ns(hrtime_t _old_ticks, hrtime_t _new_ticks);
hrtime_t acpi_timer_get_ns(void);

struct clocksource acpi_timer_source = 
{
	.name = "acpi_pm_timer",
	.rating = 200,
	.rate = ACPI_PM_TIMER_FREQUENCY,
	.get_ticks = acpi_timer_get_ticks,
	.get_ns = acpi_timer_get_ns,
	.elapsed_ns = acpi_timer_get_elapsed_ns
};

static struct fraction ns_per_tick = {NS_PER_SEC, ACPI_PM_TIMER_FREQUENCY};

hrtime_t acpi_timer_get_ns(void)
{
	uint32_t t;
	unsigned int res;
	uint32_t max = 0xffffffff;

	AcpiGetTimer(&t);

	AcpiGetTimerResolution(&res);

	if(res == 24)
		max = 0x00ffffff;

	hrtime_t ns_since_rollover = fract_mult_u64_fract(t, &ns_per_tick);

	/* HUGE TODO: MAKE THIS LOGIC THREAD SAFE */
	if(ns_since_rollover < acpi_timer_source.last_cycle)
	{
		acpi_timer_source.base += fract_mult_u64_fract(max, &ns_per_tick);
	}

	acpi_timer_source.last_cycle = ns_since_rollover;

	return acpi_timer_source.base + acpi_timer_source.monotonic_warp + ns_since_rollover;
} 

#include <onyx/timer.h>

int acpi_init_timer(void)
{
	uint32_t ticks;
	ACPI_STATUS st = AcpiGetTimer(&ticks);

	if(ACPI_FAILURE(st))
	{
		ERROR("acpi_pm_timer", "Couldn't get current ticks - there may be something "
		"wrong with the ACPI PM Timer!\n");
		return -1;
	}

	acpi_timer_source.monotonic_warp = -fract_mult_u64_fract(ticks, &ns_per_tick);
	acpi_timer_source.last_cycle = ticks;

	register_clock_source(&acpi_timer_source);
	return 0;
}

uint64_t acpi_timer_get_ticks(void)
{
	uint32_t ticks;
	AcpiGetTimer(&ticks);
	return ticks;
}

hrtime_t acpi_timer_get_elapsed_ns(hrtime_t _old_ticks, hrtime_t _new_ticks)
{
	/* Forced to rewrite this because AcpiGetTimerDuration works with 
	 * microseconds instead of nanoseconds like we want
	*/
	uint32_t delta = 0;

	/* Convert these to uint32_t's since the timer's resolution is 32-bit max. */
	uint32_t old_ticks = (uint32_t) _old_ticks;
	uint32_t new_ticks = (uint32_t) _new_ticks;

	if(old_ticks < new_ticks)
	{
		delta = new_ticks - old_ticks;
	}
	else if(old_ticks == new_ticks)
	{
		return 0;
	}
	else
	{
		unsigned int res;
		AcpiGetTimerResolution(&res);
		
		if(res == 24)
		{
			delta = ((0x00ffffff - old_ticks) + new_ticks) & 0x00ffffff;
		}
		else if(res == 32)
		{
			delta = (0xffffffff - old_ticks) + new_ticks;
		}
		else
		{
			ERROR("acpi_pm_timer", "Unknown timer resolution\n");
		}
	}

	unsigned int delta_time = delta * NS_PER_SEC / ACPI_PM_TIMER_FREQUENCY;
	return delta_time;
}

bool acpi_driver_supports_device(struct driver *driver, struct device *device)
{
	struct acpi_dev_id *dev_table = driver->devids;

	for(; dev_table->devid != NULL; dev_table++)
	{
		if(!strcmp(device->name, dev_table->devid))
		{
			return true;
		}
	}

	return false;
}

void acpi_bus_register_driver(struct driver *driver)
{
	spin_lock(&acpi_bus.bus_lock);

	if(!acpi_bus.registered_drivers)
	{
		acpi_bus.registered_drivers = driver;
	}
	else
	{
		struct driver *d;
		for(d = acpi_bus.registered_drivers; d->next_bus;
			d = d->next_bus);
		d->next_bus = driver;
	}

	driver->next_bus = NULL;

	spin_unlock(&acpi_bus.bus_lock);

	for(struct device *dev = acpi_bus.devs; dev != NULL; dev = dev->next)
	{
		if(acpi_driver_supports_device(driver, dev))
		{
			driver_register_device(driver, dev);
			if(driver->probe(dev) < 0)
				driver_deregister_device(driver, dev);
		}
	}
}
