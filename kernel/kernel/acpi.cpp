/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <errno.h>
#include <stdio.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <onyx/limits.h>

#include <onyx/mutex.h>
#include <onyx/spinlock.h>
#include <onyx/acpi.h>
#include <onyx/log.h>
#include <onyx/compiler.h>
#include <onyx/vm.h>
#include <onyx/panic.h>
#include <onyx/log.h>
#include <onyx/cpu.h>
#include <onyx/dev.h>
#include <onyx/x86/apic.h>
#include <onyx/clock.h>
#include <onyx/platform.h>
#include <onyx/init.h>
#include <onyx/bus_type.h>

#include <fixed_point/fixed_point.h>

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

uint32_t acpi_shutdown(void)
{
	AcpiEnterSleepStatePrep(5);
	irq_save_and_disable();
	AcpiEnterSleepState(5);

	panic("ACPI: Failed to enter sleep state! Panic'ing!");
	return 0;
}

extern "C" int __enter_sleep_state(uint8_t sleep_state);

unsigned int acpi_suspend(void)
{
	/* Prepare to enter S3 */
	ACPI_STATUS st = AcpiEnterSleepStatePrep(2);
	if(ACPI_FAILURE(st))
		return -EIO;
	irq_save_and_disable();
	/* We'll need to enter assembly in order to correctly save and restore
	 * registers
	*/
	if(__enter_sleep_state(2) < 0)
		return -1;
	return 0;
}

int acpi_shutdown_device(struct device *dev);
struct bus acpi_bus{"acpi"};

uint32_t acpi_execute_pic(int value)
{
	ACPI_OBJECT arg;
	ACPI_OBJECT_LIST list;

	arg.Type = ACPI_TYPE_INTEGER;
	arg.Integer.Value = value;
	list.Count = 1;
	list.Pointer = &arg;

	return AcpiEvaluateObject(ACPI_ROOT_OBJECT, (char*)"_PIC", &list, nullptr);
}

namespace acpi
{

ACPI_STATUS find_pci_buses(ACPI_HANDLE object, UINT32 nestingLevel, void *context, void **ret)
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
		find_root_pci_bus_t callback = (find_root_pci_bus_t) context;
		ACPI_BUFFER buf;
		uint64_t segment, bus;
		ACPI_OBJECT val;
		val.Type = ACPI_TYPE_INTEGER;
		buf.Pointer = &val;
		buf.Length = sizeof(val);

		if(auto st = AcpiEvaluateObject(object, (char *) "_SEG", nullptr, &buf); ACPI_FAILURE(st))
		{
			if(st == AE_NOT_FOUND)
			{
				// The spec says that if the method isn't found, we assume the segment is 0
				val.Integer.Value = 0;
			}
			else
			{
				ERROR("acpi", "Error evaluating _SEG for root bridge\n");
				free(devinfo);
				return st;
			}
		}

		segment = val.Integer.Value;

		buf.Pointer = &val;
		buf.Length = sizeof(val);

		if(auto st = AcpiEvaluateObject(object, (char *) "_BBN", nullptr, &buf); ACPI_FAILURE(st))
		{
			if(st == AE_NOT_FOUND)
			{
				// Linux seems to assume the bus is 0
				val.Integer.Value = 0;
			}
			else
			{
				ERROR("acpi", "Error evaluating _BBN for root bridge status %x\n", st);
				free(devinfo);
				return st;
			}
		}

		bus = val.Integer.Value;

		//printk("Root bridge %04x:%02x\n", (uint16_t) segment, (uint8_t) bus);

		if(callback((uint16_t) segment, (uint8_t) bus, object) < 0)
		{
			free(devinfo);
			return AE_ERROR;
		}
	}

	free(devinfo);
	return st;
}

int find_root_pci_buses(find_root_pci_bus_t callback)
{
	void* retval;
	ACPI_STATUS st = AcpiGetDevices(nullptr, find_pci_buses, (void *) callback, &retval);
	if(ACPI_FAILURE(st))
	{
		ERROR("acpi", "Error while calling AcpiGetDevices: %s\n", AcpiGbl_ExceptionNames_Env[st].Name);
		return -EIO;
	}

	return 0;
}

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

	return nullptr;
}

ACPI_RESOURCE *acpi_get_resources(ACPI_HANDLE object)
{
	ACPI_STATUS st = 0;
	ACPI_BUFFER buf;
	buf.Length = ACPI_ALLOCATE_BUFFER;
	buf.Pointer = nullptr;

	if(ACPI_FAILURE((st = AcpiGetCurrentResources(object, &buf))))
	{
		return nullptr;
	}

	return (ACPI_RESOURCE *) buf.Pointer;
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

	const char *id = nullptr;
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
		buf.Pointer = nullptr;

		st = AcpiGetName(object, ACPI_FULL_PATHNAME, &buf);
		if(ACPI_FAILURE(st))
		{
			ERROR("acpi", "AcpiGetName() failed: error %x\n", st);
			return AE_ERROR;
		}
		free_id = true;

		id = (const char *) buf.Pointer;
	}

	char *name = (char *) zalloc(PATH_MAX);
	if(!name)
		return AE_ERROR;

	snprintf(name, PATH_MAX, "%s", id);

	ACPI_RESOURCE *resources = acpi_get_resources(object);

	auto device = new acpi_device{name, &acpi_bus, nullptr, object, info, resources};
	if(!device)
	{
		free((void *) name);
		return AE_ERROR;
	}

	assert(device_init(device) == 0);
	
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
				    nullptr, nullptr, nullptr);
	if(ACPI_FAILURE(st))
	{
		ERROR("acpi", "Failed to walk the namespace\n");
	}
}

unsigned int acpi_power_event_handler(void *context)
{
	(void) context;
	return acpi_shutdown();
}

unsigned int acpi_suspend_event_handler(void *context)
{
	(void) context;
	return acpi_suspend();
}

ACPI_STATUS acpi_init_power(void)
{
	ACPI_STATUS st;
	
	if(ACPI_FAILURE((st = AcpiEnableEvent(ACPI_EVENT_POWER_BUTTON, 0))))
		return st;

	if(ACPI_FAILURE((st = AcpiInstallFixedEventHandler(ACPI_EVENT_POWER_BUTTON, acpi_power_event_handler, nullptr))))
		return st;

	if(ACPI_FAILURE((st = AcpiInstallFixedEventHandler(ACPI_EVENT_SLEEP_BUTTON, acpi_suspend_event_handler, nullptr))))
		return st;
	
	return AE_OK;
}

void acpi_initialise(void)
{
	acpi_find_rsdp();
	ACPI_STATUS st = AcpiInitializeSubsystem();
	if(ACPI_FAILURE(st))
	{
		printk("Error: %s\n", AcpiGbl_ExceptionNames_Env[st].Name);
		panic("ACPI subsystem initialization failed!");
	}

	st = AcpiInitializeTables(nullptr, 32, true);
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
	
	assert(bus_init(&acpi_bus) == 0);

	/* Enumerate every device */
	acpi_enumerate_devices();

	/* Register the acpi bus */
	bus_register(&acpi_bus);

	platform_init_acpi();

	acpi_init_power();
}

INIT_LEVEL_VERY_EARLY_PLATFORM_ENTRY(acpi_initialise);

uint32_t acpi_get_apic_id_lapic(ACPI_SUBTABLE_HEADER *madt)
{
	return ((ACPI_MADT_LOCAL_APIC*) madt)->Id;
}

static DECLARE_MUTEX(cpu_enum_lock);

static size_t __ndx = 0;

// TODO: Parts of this are arch specific

ACPI_STATUS acpi_enumerate_per_cpu(ACPI_HANDLE object, UINT32 nestingLevel, void *context, void **returnvalue)
{
	ACPI_BUFFER buffer = { ACPI_ALLOCATE_BUFFER, nullptr};
	struct acpi_processor *processor = &((struct acpi_processor *) context)[__ndx++];
	uint32_t apic_id = (uint32_t) -1;
	(void) apic_id;

	/* _MAT returns a segment of the MADT table */
	if(ACPI_FAILURE(AcpiEvaluateObject(object, (char *) "_MAT", nullptr, &buffer)))
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

#if __x86_64__
	processor->apic_id = apic_id;
#endif

	ACPI_FREE(buffer.Pointer);
	return AE_OK;
}

struct acpi_processor *acpi_enumerate_cpus(void)
{
	acpi_processor *processors = (acpi_processor *) malloc(sizeof(acpi_processor) * get_nr_cpus());
	if(!processors)
	{
		return nullptr;
	}

	memset(processors, 0, sizeof(struct acpi_processor) * get_nr_cpus());

	mutex_lock(&cpu_enum_lock);

	__ndx = 0;
	/* Walk the namespace, looking for ACPI PROCESSOR objects */
	AcpiWalkNamespace(ACPI_TYPE_PROCESSOR, ACPI_ROOT_OBJECT,
				    ACPI_UINT32_MAX,
				    acpi_enumerate_per_cpu,
				    nullptr, processors, nullptr);

	mutex_unlock(&cpu_enum_lock);
	return processors;
}

struct acpi_device *acpi_get_device(const char *id)
{
	return (struct acpi_device*) bus_find_device(&acpi_bus, id);
}

const char *power_states[] =
{
	"_PS0",
	"_PS1",
	"_PS2",
	"_PS3"
};

int acpi_set_device_power_state(struct acpi_device *device, unsigned int power_state)
{
	ACPI_STATUS st = AcpiEvaluateObject(device->object, (char *) power_states[power_state], nullptr, nullptr);
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
	.rating = 150,
	.rate = ACPI_PM_TIMER_FREQUENCY,
	.get_ticks = acpi_timer_get_ticks,
	.get_ns = acpi_timer_get_ns,
	.elapsed_ns = acpi_timer_get_elapsed_ns
};

static struct fp_32_64 acpi_timer_ticks_per_ns;

hrtime_t acpi_timer_get_ns(void)
{
	uint32_t t;
	unsigned int res;
	uint32_t max = 0xffffffff;

	AcpiGetTimer(&t);

	AcpiGetTimerResolution(&res);

	if(res == 24)
		max = 0x00ffffff;

	hrtime_t ns_since_rollover = u64_mul_u32_fp32_64(t, acpi_timer_ticks_per_ns);

	if(ns_since_rollover < acpi_timer_source.last_cycle)
	{
		acpi_timer_source.base += u64_mul_u32_fp32_64(max, acpi_timer_ticks_per_ns);
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

	fp_32_64_div_32_32(&acpi_timer_ticks_per_ns, NS_PER_SEC, ACPI_PM_TIMER_FREQUENCY);

	acpi_timer_source.monotonic_warp = -u64_mul_u32_fp32_64(ticks, acpi_timer_ticks_per_ns);
	acpi_timer_source.last_cycle = ticks;

	AcpiGetTimerResolution(&acpi_timer_source.resolution);
	acpi_timer_source.ticks_per_ns = &acpi_timer_ticks_per_ns;

	register_clock_source(&acpi_timer_source);

	hrtime_t t0 = clocksource_get_time();

	(void) t0;
	//while(true) {}
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
	struct acpi_dev_id *dev_table = (acpi_dev_id *) driver->devids;

	for(; dev_table->devid != nullptr; dev_table++)
	{
		if(!strcmp(device->name, dev_table->devid))
		{
			return true;
		}
	}

	return false;
}

bus_type acpi_type{"acpi"};

void acpi_bus_register_driver(struct driver *driver)
{
	acpi_type.add_driver(driver);

	// TODO: Move this to the bus implementation
	list_for_every(&acpi_bus.device_list_head)
	{
		struct device *dev = list_head_cpp<device>::self_from_list_head(l);
		if(acpi_driver_supports_device(driver, dev))
		{
			driver_register_device(driver, dev);
			if(driver->probe(dev) < 0)
				driver_deregister_device(driver, dev);
		}
	}
}
