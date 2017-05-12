/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_SMBIOS_H
#define _KERNEL_SMBIOS_H

#include <stdint.h>

struct smbios_entrypoint32
{
	char sig[4]; /* _SM_ */
	uint8_t checksum;
	uint8_t len; /* The length of this structure */
	uint8_t smbios_major; /* Major version of the spec */
	uint8_t smbios_minor; /* Minor version of the spec */
	uint16_t largest_struct_size;
	uint8_t formatted_area[5];
	char intermediate_sig[5]; /* _DMI_ */
	uint8_t intermediate_checksum;
	uint32_t addr;
	uint16_t nr_smbios_structs;
	uint8_t bcd_revision;
};
struct smbios_entrypoint64
{
	char sig[5]; /* _SM3_ */
	uint8_t checksum;
	uint16_t len;
	uint8_t smbios_major;
	uint8_t smbios_minor;
	uint8_t docrev;
	uint8_t entrypoint_rev;
	uint8_t res;
	uint32_t struct_max_size;
	uint64_t addr;
};
/* Note that the kernel will prefer the 64-bit structure to the 32-bit one, 
 * and will only use the latter as a fallback */

struct smbios_table
{
	uint8_t type;
	uint8_t len;
	uint16_t handle;
};

#define SMBIOS_TYPE_BIOS_INFO			0
#define SMBIOS_TYPE_SYSTEM_INFO			1
#define SMBIOS_TYPE_SYSTEM_ENCLOSURE		3
#define SMBIOS_TYPE_PROCESSOR_INFO		4
#define SMBIOS_TYPE_CACHE_INFO			7
#define SMBIOS_TYPE_SYSTEM_SLOTS		9
#define SMBIOS_TYPE_PHYS_MEM_ARRAY		16
#define SMBIOS_TYPE_MEM_DEVICE			17
#define SMBIOS_TYPE_MEM_ARRAY_MAPPED_ADDR	19
#define SMBIOS_TYPE_SYSTEM_BOOT_INFO		32

struct smbios_table_bios_info
{
	struct smbios_table header;
	uint8_t vendor;
	uint8_t bios_version;
	uint16_t bios_start_addr_segment;
	uint8_t bios_release_date;
	uint8_t bios_rom_size;
	uint64_t bios_characteristics;
	union
	{
		uint8_t bios_characteristics_ext[2];
		uint16_t majorminor;
	} u_bios;

	uint8_t embedded_controller_major;
	uint8_t embedded_controller_minor;
	uint8_t ext_bios_rom_size;

	/* Points to the string table after the formatted part of the struct */
	char strings[0];
};
int smbios_init(void);
char *smbios_get_string(struct smbios_table *t, uint8_t strndx);
struct smbios_table *smbios_get_table(int type);

#endif
