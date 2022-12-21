/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/******************************************************************************
 *
 * Name: acdisasm.h - AML disassembler
 *
 * Copyright (C) 2000 - 2022, Intel Corp.
 *
 *****************************************************************************/


#ifndef __ACDISASM_H__
#define __ACDISASM_H__

#include "amlresrc.h"


#define BLOCK_NONE              0
#define BLOCK_PAREN             1
#define BLOCK_BRACE             2
#define BLOCK_COMMA_LIST        4
#define ACPI_DEFAULT_RESNAME    *(u32 *) "__RD"

/*
 * Raw table data header. Used by disassembler and data table compiler.
 * Do not change.
 */
#define ACPI_RAW_TABLE_DATA_HEADER      "Raw Table Data"


struct acpi_dmtable_info
{
	u8                                  opcode;
	u16                                 offset;
	char                                *name;
	u8                                  flags;
};

/* Values for Flags field above */

#define DT_LENGTH                       0x01    /* Field is a subtable length */
#define DT_FLAG                         0x02    /* Field is a flag value */
#define DT_NON_ZERO                     0x04    /* Field must be non-zero */
#define DT_OPTIONAL                     0x08    /* Field is optional */
#define DT_DESCRIBES_OPTIONAL           0x10    /* Field describes an optional field (length, etc.) */
#define DT_COUNT                        0x20    /* Currently not used */

/*
 * Values for Opcode above.
 * Note: 0-7 must not change, they are used as a flag shift value. Other
 * than those, new values can be added wherever appropriate.
 */
typedef enum
{
	/* Simple Data Types */

	ACPI_DMT_FLAG0          = 0,
	ACPI_DMT_FLAG1          = 1,
	ACPI_DMT_FLAG2          = 2,
	ACPI_DMT_FLAG3          = 3,
	ACPI_DMT_FLAG4          = 4,
	ACPI_DMT_FLAG5          = 5,
	ACPI_DMT_FLAG6          = 6,
	ACPI_DMT_FLAG7          = 7,
	ACPI_DMT_FLAGS0,
	ACPI_DMT_FLAGS1,
	ACPI_DMT_FLAGS2,
	ACPI_DMT_FLAGS8_2,
	ACPI_DMT_FLAGS4,
	ACPI_DMT_FLAGS4_0,
	ACPI_DMT_FLAGS4_4,
	ACPI_DMT_FLAGS4_8,
	ACPI_DMT_FLAGS4_12,
	ACPI_DMT_FLAGS16_16,
	ACPI_DMT_UINT8,
	ACPI_DMT_UINT16,
	ACPI_DMT_UINT24,
	ACPI_DMT_UINT32,
	ACPI_DMT_UINT40,
	ACPI_DMT_UINT48,
	ACPI_DMT_UINT56,
	ACPI_DMT_UINT64,
	ACPI_DMT_BUF7,
	ACPI_DMT_BUF10,
	ACPI_DMT_BUF12,
	ACPI_DMT_BUF16,
	ACPI_DMT_BUF18,
	ACPI_DMT_BUF128,
	ACPI_DMT_SIG,
	ACPI_DMT_STRING,
	ACPI_DMT_NAME4,
	ACPI_DMT_NAME6,
	ACPI_DMT_NAME8,

	/* Types that are decoded to strings and miscellaneous */

	ACPI_DMT_ACCWIDTH,
	ACPI_DMT_CHKSUM,
	ACPI_DMT_GAS,
	ACPI_DMT_SPACEID,
	ACPI_DMT_UNICODE,
	ACPI_DMT_UUID,

	/* Types used only for the Data Table Compiler */

	ACPI_DMT_BUFFER,
	ACPI_DMT_RAW_BUFFER,  /* Large, multiple line buffer */
	ACPI_DMT_DEVICE_PATH,
	ACPI_DMT_LABEL,
	ACPI_DMT_PCI_PATH,

	/* Types that are specific to particular ACPI tables */

	ACPI_DMT_AEST,
	ACPI_DMT_AEST_CACHE,
	ACPI_DMT_AEST_GIC,
	ACPI_DMT_AEST_RES,
	ACPI_DMT_AEST_XFACE,
	ACPI_DMT_AEST_XRUPT,
	ACPI_DMT_AGDI,
	ACPI_DMT_ASF,
	ACPI_DMT_CDAT,
	ACPI_DMT_CEDT,
	ACPI_DMT_DMAR,
	ACPI_DMT_DMAR_SCOPE,
	ACPI_DMT_EINJACT,
	ACPI_DMT_EINJINST,
	ACPI_DMT_ERSTACT,
	ACPI_DMT_ERSTINST,
	ACPI_DMT_FADTPM,
	ACPI_DMT_GTDT,
	ACPI_DMT_HEST,
	ACPI_DMT_HESTNTFY,
	ACPI_DMT_HESTNTYP,
	ACPI_DMT_HMAT,
	ACPI_DMT_IORTMEM,
	ACPI_DMT_IVRS,
	ACPI_DMT_IVRS_DE,
	ACPI_DMT_IVRS_UNTERMINATED_STRING,
	ACPI_DMT_LPIT,
	ACPI_DMT_MADT,
	ACPI_DMT_NFIT,
	ACPI_DMT_NHLT1,
	ACPI_DMT_NHLT1a,
	ACPI_DMT_NHLT1b,
	ACPI_DMT_NHLT1c,
	ACPI_DMT_NHLT1d,
	ACPI_DMT_NHLT1e,
	ACPI_DMT_NHLT1f,
	ACPI_DMT_PCCT,
	ACPI_DMT_PHAT,
	ACPI_DMT_PMTT,
	ACPI_DMT_PMTT_VENDOR,
	ACPI_DMT_PPTT,
	ACPI_DMT_RGRT,
	ACPI_DMT_SDEI,
	ACPI_DMT_SDEV,
	ACPI_DMT_SLIC,
	ACPI_DMT_SRAT,
	ACPI_DMT_TPM2,
	ACPI_DMT_VIOT,
	ACPI_DMT_WPBT_UNICODE,

	/* Special opcodes */

	ACPI_DMT_EXTRA_TEXT,
	ACPI_DMT_EXIT

} ACPI_ENTRY_TYPES;

typedef
void (*acpi_dmtable_handler) (
	struct acpi_table_header        *table);

typedef
acpi_status (*acpi_cmtable_handler) (
	void                            **pfield_list);

struct acpi_dmtable_data
{
	char                            *signature;
	struct acpi_dmtable_info        *table_info;
	acpi_dmtable_handler            table_handler;
	acpi_cmtable_handler            cm_table_handler;
	const unsigned char     *template;
};


struct acpi_op_walk_info
{
	struct acpi_walk_state          *walk_state;
	union acpi_parse_object         *mapping_op;
	u8                              *previous_aml;
	u8                              *start_aml;
	u32                             level;
	u32                             last_level;
	u32                             count;
	u32                             bit_offset;
	u32                             flags;
	u32                             aml_offset;
};

/*
 * TBD - another copy of this is in asltypes.h, fix
 */
#ifndef ASL_WALK_CALLBACK_DEFINED
typedef
acpi_status (*asl_walk_callback) (
	union acpi_parse_object             *op,
	u32                                 level,
	void                                *context);
#define ASL_WALK_CALLBACK_DEFINED
#endif

typedef
void (*acpi_resource_handler) (
	struct acpi_op_walk_info        *info,
	union aml_resource              *resource,
	u32                             length,
	u32                             level);

struct acpi_resource_tag
{
	u32                             bit_index;
	char                            *tag;
};

/* Strings used for decoding flags to ASL keywords */

extern const char                       *acpi_gbl_word_decode[];
extern const char                       *acpi_gbl_irq_decode[];
extern const char                       *acpi_gbl_lock_rule[];
extern const char                       *acpi_gbl_access_types[];
extern const char                       *acpi_gbl_update_rules[];
extern const char                       *acpi_gbl_match_ops[];

extern struct acpi_dmtable_info         acpi_dm_table_info_aest_hdr[];
extern struct acpi_dmtable_info         acpi_dm_table_info_aest_proc_error[];
extern struct acpi_dmtable_info         acpi_dm_table_info_aest_cache_rsrc[];
extern struct acpi_dmtable_info         acpi_dm_table_info_aest_tlb_rsrc[];
extern struct acpi_dmtable_info         acpi_dm_table_info_aest_gen_rsrc[];
extern struct acpi_dmtable_info         acpi_dm_table_info_aest_mem_error[];
extern struct acpi_dmtable_info         acpi_dm_table_info_aest_smmu_error[];
extern struct acpi_dmtable_info         acpi_dm_table_info_aest_vendor_error[];
extern struct acpi_dmtable_info         acpi_dm_table_info_aest_gic_error[];
extern struct acpi_dmtable_info         acpi_dm_table_info_aest_xface[];
extern struct acpi_dmtable_info         acpi_dm_table_info_aest_xrupt[];
extern struct acpi_dmtable_info         acpi_dm_table_info_agdi[];
extern struct acpi_dmtable_info         acpi_dm_table_info_apmt_node[];
extern struct acpi_dmtable_info         acpi_dm_table_info_asf0[];
extern struct acpi_dmtable_info         acpi_dm_table_info_asf1[];
extern struct acpi_dmtable_info         acpi_dm_table_info_asf1a[];
extern struct acpi_dmtable_info         acpi_dm_table_info_asf2[];
extern struct acpi_dmtable_info         acpi_dm_table_info_asf2a[];
extern struct acpi_dmtable_info         acpi_dm_table_info_asf3[];
extern struct acpi_dmtable_info         acpi_dm_table_info_asf4[];
extern struct acpi_dmtable_info         acpi_dm_table_info_asf_hdr[];
extern struct acpi_dmtable_info         acpi_dm_table_info_bdat[];
extern struct acpi_dmtable_info         acpi_dm_table_info_boot[];
extern struct acpi_dmtable_info         acpi_dm_table_info_bert[];
extern struct acpi_dmtable_info         acpi_dm_table_info_bgrt[];
extern struct acpi_dmtable_info         acpi_dm_table_info_ccel[];
extern struct acpi_dmtable_info         acpi_dm_table_info_cdat_table_hdr[];
extern struct acpi_dmtable_info         acpi_dm_table_info_cdat_header[];
extern struct acpi_dmtable_info         acpi_dm_table_info_cdat0[];
extern struct acpi_dmtable_info         acpi_dm_table_info_cdat1[];
extern struct acpi_dmtable_info         acpi_dm_table_info_cdat2[];
extern struct acpi_dmtable_info         acpi_dm_table_info_cdat3[];
extern struct acpi_dmtable_info         acpi_dm_table_info_cdat4[];
extern struct acpi_dmtable_info         acpi_dm_table_info_cdat5[];
extern struct acpi_dmtable_info         acpi_dm_table_info_cdat_entries[];
extern struct acpi_dmtable_info         acpi_dm_table_info_cedt_hdr[];
extern struct acpi_dmtable_info         acpi_dm_table_info_cedt0[];
extern struct acpi_dmtable_info         acpi_dm_table_info_cedt1[];
extern struct acpi_dmtable_info         acpi_dm_table_info_cedt1_te[];
extern struct acpi_dmtable_info         acpi_dm_table_info_cpep[];
extern struct acpi_dmtable_info         acpi_dm_table_info_cpep0[];
extern struct acpi_dmtable_info         acpi_dm_table_info_csrt0[];
extern struct acpi_dmtable_info         acpi_dm_table_info_csrt1[];
extern struct acpi_dmtable_info         acpi_dm_table_info_csrt2[];
extern struct acpi_dmtable_info         acpi_dm_table_info_csrt2a[];
extern struct acpi_dmtable_info         acpi_dm_table_info_dbg2[];
extern struct acpi_dmtable_info         acpi_dm_table_info_dbg2_device[];
extern struct acpi_dmtable_info         acpi_dm_table_info_dbg2_addr[];
extern struct acpi_dmtable_info         acpi_dm_table_info_dbg2_size[];
extern struct acpi_dmtable_info         acpi_dm_table_info_dbg2_name[];
extern struct acpi_dmtable_info         acpi_dm_table_info_dbg2_oem_data[];
extern struct acpi_dmtable_info         acpi_dm_table_info_dbgp[];
extern struct acpi_dmtable_info         acpi_dm_table_info_dmar[];
extern struct acpi_dmtable_info         acpi_dm_table_info_dmar_hdr[];
extern struct acpi_dmtable_info         acpi_dm_table_info_dmar_scope[];
extern struct acpi_dmtable_info         acpi_dm_table_info_dmar0[];
extern struct acpi_dmtable_info         acpi_dm_table_info_dmar1[];
extern struct acpi_dmtable_info         acpi_dm_table_info_dmar2[];
extern struct acpi_dmtable_info         acpi_dm_table_info_dmar3[];
extern struct acpi_dmtable_info         acpi_dm_table_info_dmar4[];
extern struct acpi_dmtable_info         acpi_dm_table_info_dmar5[];
extern struct acpi_dmtable_info         acpi_dm_table_info_drtm[];
extern struct acpi_dmtable_info         acpi_dm_table_info_drtm0[];
extern struct acpi_dmtable_info         acpi_dm_table_info_drtm0a[];
extern struct acpi_dmtable_info         acpi_dm_table_info_drtm1[];
extern struct acpi_dmtable_info         acpi_dm_table_info_drtm1a[];
extern struct acpi_dmtable_info         acpi_dm_table_info_drtm2[];
extern struct acpi_dmtable_info         acpi_dm_table_info_ecdt[];
extern struct acpi_dmtable_info         acpi_dm_table_info_einj[];
extern struct acpi_dmtable_info         acpi_dm_table_info_einj0[];
extern struct acpi_dmtable_info         acpi_dm_table_info_erst[];
extern struct acpi_dmtable_info         acpi_dm_table_info_erst0[];
extern struct acpi_dmtable_info         acpi_dm_table_info_facs[];
extern struct acpi_dmtable_info         acpi_dm_table_info_fadt1[];
extern struct acpi_dmtable_info         acpi_dm_table_info_fadt2[];
extern struct acpi_dmtable_info         acpi_dm_table_info_fadt3[];
extern struct acpi_dmtable_info         acpi_dm_table_info_fadt5[];
extern struct acpi_dmtable_info         acpi_dm_table_info_fadt6[];
extern struct acpi_dmtable_info         acpi_dm_table_info_fpdt[];
extern struct acpi_dmtable_info         acpi_dm_table_info_fpdt_hdr[];
extern struct acpi_dmtable_info         acpi_dm_table_info_fpdt0[];
extern struct acpi_dmtable_info         acpi_dm_table_info_fpdt1[];
extern struct acpi_dmtable_info         acpi_dm_table_info_gas[];
extern struct acpi_dmtable_info         acpi_dm_table_info_gtdt[];
extern struct acpi_dmtable_info         acpi_dm_table_info_gtdt_hdr[];
extern struct acpi_dmtable_info         acpi_dm_table_info_gtdt_el2[];
extern struct acpi_dmtable_info         acpi_dm_table_info_gtdt0[];
extern struct acpi_dmtable_info         acpi_dm_table_info_gtdt0a[];
extern struct acpi_dmtable_info         acpi_dm_table_info_gtdt1[];
extern struct acpi_dmtable_info         acpi_dm_table_info_header[];
extern struct acpi_dmtable_info         acpi_dm_table_info_hest[];
extern struct acpi_dmtable_info         acpi_dm_table_info_hest0[];
extern struct acpi_dmtable_info         acpi_dm_table_info_hest1[];
extern struct acpi_dmtable_info         acpi_dm_table_info_hest2[];
extern struct acpi_dmtable_info         acpi_dm_table_info_hest6[];
extern struct acpi_dmtable_info         acpi_dm_table_info_hest7[];
extern struct acpi_dmtable_info         acpi_dm_table_info_hest8[];
extern struct acpi_dmtable_info         acpi_dm_table_info_hest9[];
extern struct acpi_dmtable_info         acpi_dm_table_info_hest10[];
extern struct acpi_dmtable_info         acpi_dm_table_info_hest11[];
extern struct acpi_dmtable_info         acpi_dm_table_info_hest_notify[];
extern struct acpi_dmtable_info         acpi_dm_table_info_hest_bank[];
extern struct acpi_dmtable_info         acpi_dm_table_info_hpet[];
extern struct acpi_dmtable_info         acpi_dm_table_info_lpit_hdr[];
extern struct acpi_dmtable_info         acpi_dm_table_info_lpit0[];
extern struct acpi_dmtable_info         acpi_dm_table_info_lpit1[];
extern struct acpi_dmtable_info         acpi_dm_table_info_hmat[];
extern struct acpi_dmtable_info         acpi_dm_table_info_hmat0[];
extern struct acpi_dmtable_info         acpi_dm_table_info_hmat1[];
extern struct acpi_dmtable_info         acpi_dm_table_info_hmat1a[];
extern struct acpi_dmtable_info         acpi_dm_table_info_hmat1b[];
extern struct acpi_dmtable_info         acpi_dm_table_info_hmat1c[];
extern struct acpi_dmtable_info         acpi_dm_table_info_hmat2[];
extern struct acpi_dmtable_info         acpi_dm_table_info_hmat2a[];
extern struct acpi_dmtable_info         acpi_dm_table_info_hmat_hdr[];
extern struct acpi_dmtable_info         acpi_dm_table_info_iort[];
extern struct acpi_dmtable_info         acpi_dm_table_info_iort0[];
extern struct acpi_dmtable_info         acpi_dm_table_info_iort0a[];
extern struct acpi_dmtable_info         acpi_dm_table_info_iort1[];
extern struct acpi_dmtable_info         acpi_dm_table_info_iort1a[];
extern struct acpi_dmtable_info         acpi_dm_table_info_iort2[];
extern struct acpi_dmtable_info         acpi_dm_table_info_iort3[];
extern struct acpi_dmtable_info         acpi_dm_table_info_iort3a[];
extern struct acpi_dmtable_info         acpi_dm_table_info_iort3b[];
extern struct acpi_dmtable_info         acpi_dm_table_info_iort3c[];
extern struct acpi_dmtable_info         acpi_dm_table_info_iort4[];
extern struct acpi_dmtable_info         acpi_dm_table_info_iort5[];
extern struct acpi_dmtable_info         acpi_dm_table_info_iort6[];
extern struct acpi_dmtable_info         acpi_dm_table_info_iort6a[];
extern struct acpi_dmtable_info         acpi_dm_table_info_iort_acc[];
extern struct acpi_dmtable_info         acpi_dm_table_info_iort_hdr[];
extern struct acpi_dmtable_info         acpi_dm_table_info_iort_hdr3[];
extern struct acpi_dmtable_info         acpi_dm_table_info_iort_map[];
extern struct acpi_dmtable_info         acpi_dm_table_info_iort_pad[];
extern struct acpi_dmtable_info         acpi_dm_table_info_ivrs[];
extern struct acpi_dmtable_info         acpi_dm_table_info_ivrs_hware1[];
extern struct acpi_dmtable_info         acpi_dm_table_info_ivrs_hware23[];
extern struct acpi_dmtable_info         acpi_dm_table_info_ivrs_memory[];
extern struct acpi_dmtable_info         acpi_dm_table_info_ivrs4[];
extern struct acpi_dmtable_info         acpi_dm_table_info_ivrs8a[];
extern struct acpi_dmtable_info         acpi_dm_table_info_ivrs8b[];
extern struct acpi_dmtable_info         acpi_dm_table_info_ivrs8c[];
extern struct acpi_dmtable_info         acpi_dm_table_info_ivrs_cid_string[];
extern struct acpi_dmtable_info         acpi_dm_table_info_ivrs_cid_integer[];
extern struct acpi_dmtable_info         acpi_dm_table_info_ivrs_hid[];
extern struct acpi_dmtable_info         acpi_dm_table_info_ivrs_uid_string[];
extern struct acpi_dmtable_info         acpi_dm_table_info_ivrs_uid_integer[];
extern struct acpi_dmtable_info         acpi_dm_table_info_ivrs_hid_string[];
extern struct acpi_dmtable_info         acpi_dm_table_info_ivrs_hid_integer[];
extern struct acpi_dmtable_info         acpi_dm_table_info_madt[];
extern struct acpi_dmtable_info         acpi_dm_table_info_madt0[];
extern struct acpi_dmtable_info         acpi_dm_table_info_madt1[];
extern struct acpi_dmtable_info         acpi_dm_table_info_madt2[];
extern struct acpi_dmtable_info         acpi_dm_table_info_madt3[];
extern struct acpi_dmtable_info         acpi_dm_table_info_madt4[];
extern struct acpi_dmtable_info         acpi_dm_table_info_madt5[];
extern struct acpi_dmtable_info         acpi_dm_table_info_madt6[];
extern struct acpi_dmtable_info         acpi_dm_table_info_madt7[];
extern struct acpi_dmtable_info         acpi_dm_table_info_madt8[];
extern struct acpi_dmtable_info         acpi_dm_table_info_madt9[];
extern struct acpi_dmtable_info         acpi_dm_table_info_madt10[];
extern struct acpi_dmtable_info         acpi_dm_table_info_madt11[];
extern struct acpi_dmtable_info         acpi_dm_table_info_madt12[];
extern struct acpi_dmtable_info         acpi_dm_table_info_madt13[];
extern struct acpi_dmtable_info         acpi_dm_table_info_madt14[];
extern struct acpi_dmtable_info         acpi_dm_table_info_madt15[];
extern struct acpi_dmtable_info         acpi_dm_table_info_madt16[];
extern struct acpi_dmtable_info         acpi_dm_table_info_madt17[];
extern struct acpi_dmtable_info         acpi_dm_table_info_madt_hdr[];
extern struct acpi_dmtable_info         acpi_dm_table_info_mcfg[];
extern struct acpi_dmtable_info         acpi_dm_table_info_mcfg0[];
extern struct acpi_dmtable_info         acpi_dm_table_info_mchi[];
extern struct acpi_dmtable_info         acpi_dm_table_info_mpst[];
extern struct acpi_dmtable_info         acpi_dm_table_info_mpst0[];
extern struct acpi_dmtable_info         acpi_dm_table_info_mpst0_a[];
extern struct acpi_dmtable_info         acpi_dm_table_info_mpst0_b[];
extern struct acpi_dmtable_info         acpi_dm_table_info_mpst1[];
extern struct acpi_dmtable_info         acpi_dm_table_info_mpst2[];
extern struct acpi_dmtable_info         acpi_dm_table_info_msct[];
extern struct acpi_dmtable_info         acpi_dm_table_info_msct0[];
extern struct acpi_dmtable_info         acpi_dm_table_info_nfit[];
extern struct acpi_dmtable_info         acpi_dm_table_info_nfit_hdr[];
extern struct acpi_dmtable_info         acpi_dm_table_info_nfit0[];
extern struct acpi_dmtable_info         acpi_dm_table_info_nfit1[];
extern struct acpi_dmtable_info         acpi_dm_table_info_nfit2[];
extern struct acpi_dmtable_info         acpi_dm_table_info_nfit2a[];
extern struct acpi_dmtable_info         acpi_dm_table_info_nfit3[];
extern struct acpi_dmtable_info         acpi_dm_table_info_nfit3a[];
extern struct acpi_dmtable_info         acpi_dm_table_info_nfit4[];
extern struct acpi_dmtable_info         acpi_dm_table_info_nfit5[];
extern struct acpi_dmtable_info         acpi_dm_table_info_nfit6[];
extern struct acpi_dmtable_info         acpi_dm_table_info_nfit6a[];
extern struct acpi_dmtable_info         acpi_dm_table_info_nfit7[];
extern struct acpi_dmtable_info         acpi_dm_table_info_nhlt[];
extern struct acpi_dmtable_info         acpi_dm_table_info_nhlt0[];
extern struct acpi_dmtable_info         acpi_dm_table_info_nhlt1[];
extern struct acpi_dmtable_info         acpi_dm_table_info_nhlt2[];
extern struct acpi_dmtable_info         acpi_dm_table_info_nhlt3[];
extern struct acpi_dmtable_info         acpi_dm_table_info_nhlt3a[];
extern struct acpi_dmtable_info         acpi_dm_table_info_nhlt4[];
extern struct acpi_dmtable_info         acpi_dm_table_info_nhlt5[];
extern struct acpi_dmtable_info         acpi_dm_table_info_nhlt5a[];
extern struct acpi_dmtable_info         acpi_dm_table_info_nhlt5b[];
extern struct acpi_dmtable_info         acpi_dm_table_info_nhlt5c[];
extern struct acpi_dmtable_info         acpi_dm_table_info_nhlt6[];
extern struct acpi_dmtable_info         acpi_dm_table_info_nhlt6a[];
extern struct acpi_dmtable_info         acpi_dm_table_info_nhlt6b[];
extern struct acpi_dmtable_info         acpi_dm_table_info_nhlt7[];
extern struct acpi_dmtable_info         acpi_dm_table_info_nhlt7a[];
extern struct acpi_dmtable_info         acpi_dm_table_info_nhlt7b[];
extern struct acpi_dmtable_info         acpi_dm_table_info_nhlt9[];
extern struct acpi_dmtable_info         acpi_dm_table_info_phat_hdr[];
extern struct acpi_dmtable_info         acpi_dm_table_info_phat0[];
extern struct acpi_dmtable_info         acpi_dm_table_info_phat0a[];
extern struct acpi_dmtable_info         acpi_dm_table_info_phat1[];
extern struct acpi_dmtable_info         acpi_dm_table_info_phat1a[];
extern struct acpi_dmtable_info         acpi_dm_table_info_phat1b[];
extern struct acpi_dmtable_info         acpi_dm_table_info_pmtt[];
extern struct acpi_dmtable_info         acpi_dm_table_info_pmtt0[];
extern struct acpi_dmtable_info         acpi_dm_table_info_pmtt1[];
extern struct acpi_dmtable_info         acpi_dm_table_info_pmtt2[];
extern struct acpi_dmtable_info         acpi_dm_table_info_pmtt_vendor[];
extern struct acpi_dmtable_info         acpi_dm_table_info_pmtt_hdr[];
extern struct acpi_dmtable_info         acpi_dm_table_info_pcct[];
extern struct acpi_dmtable_info         acpi_dm_table_info_pcct_hdr[];
extern struct acpi_dmtable_info         acpi_dm_table_info_pcct0[];
extern struct acpi_dmtable_info         acpi_dm_table_info_pcct1[];
extern struct acpi_dmtable_info         acpi_dm_table_info_pcct2[];
extern struct acpi_dmtable_info         acpi_dm_table_info_pcct3[];
extern struct acpi_dmtable_info         acpi_dm_table_info_pcct4[];
extern struct acpi_dmtable_info         acpi_dm_table_info_pcct5[];
extern struct acpi_dmtable_info         acpi_dm_table_info_pdtt[];
extern struct acpi_dmtable_info         acpi_dm_table_info_pdtt0[];
extern struct acpi_dmtable_info         acpi_dm_table_info_pptt0[];
extern struct acpi_dmtable_info         acpi_dm_table_info_pptt0a[];
extern struct acpi_dmtable_info         acpi_dm_table_info_pptt1[];
extern struct acpi_dmtable_info         acpi_dm_table_info_pptt1a[];
extern struct acpi_dmtable_info         acpi_dm_table_info_pptt2[];
extern struct acpi_dmtable_info         acpi_dm_table_info_pptt_hdr[];
extern struct acpi_dmtable_info         acpi_dm_table_info_prmt_hdr[];
extern struct acpi_dmtable_info         acpi_dm_table_info_prmt_module[];
extern struct acpi_dmtable_info         acpi_dm_table_info_prmt_handler[];
extern struct acpi_dmtable_info         acpi_dm_table_info_rasf[];
extern struct acpi_dmtable_info         acpi_dm_table_info_rgrt[];
extern struct acpi_dmtable_info         acpi_dm_table_info_rgrt0[];
extern struct acpi_dmtable_info         acpi_dm_table_info_rsdp1[];
extern struct acpi_dmtable_info         acpi_dm_table_info_rsdp2[];
extern struct acpi_dmtable_info         acpi_dm_table_info_s3pt[];
extern struct acpi_dmtable_info         acpi_dm_table_info_s3pt_hdr[];
extern struct acpi_dmtable_info         acpi_dm_table_info_s3pt0[];
extern struct acpi_dmtable_info         acpi_dm_table_info_s3pt1[];
extern struct acpi_dmtable_info         acpi_dm_table_info_sbst[];
extern struct acpi_dmtable_info         acpi_dm_table_info_sdei[];
extern struct acpi_dmtable_info         acpi_dm_table_info_sdev[];
extern struct acpi_dmtable_info         acpi_dm_table_info_sdev_hdr[];
extern struct acpi_dmtable_info         acpi_dm_table_info_sdev0[];
extern struct acpi_dmtable_info         acpi_dm_table_info_sdev0a[];
extern struct acpi_dmtable_info         acpi_dm_table_info_sdev0b[];
extern struct acpi_dmtable_info         acpi_dm_table_info_sdev_sec_comp_hdr[];
extern struct acpi_dmtable_info         acpi_dm_table_info_sdev_sec_comp_id[];
extern struct acpi_dmtable_info         acpi_dm_table_info_sdev_sec_comp_mem[];
extern struct acpi_dmtable_info         acpi_dm_table_info_sdev1[];
extern struct acpi_dmtable_info         acpi_dm_table_info_sdev1a[];
extern struct acpi_dmtable_info         acpi_dm_table_info_sdev1b[];
extern struct acpi_dmtable_info         acpi_dm_table_info_slic[];
extern struct acpi_dmtable_info         acpi_dm_table_info_slit[];
extern struct acpi_dmtable_info         acpi_dm_table_info_spcr[];
extern struct acpi_dmtable_info         acpi_dm_table_info_spmi[];
extern struct acpi_dmtable_info         acpi_dm_table_info_srat[];
extern struct acpi_dmtable_info         acpi_dm_table_info_srat_hdr[];
extern struct acpi_dmtable_info         acpi_dm_table_info_srat0[];
extern struct acpi_dmtable_info         acpi_dm_table_info_srat1[];
extern struct acpi_dmtable_info         acpi_dm_table_info_srat2[];
extern struct acpi_dmtable_info         acpi_dm_table_info_srat3[];
extern struct acpi_dmtable_info         acpi_dm_table_info_srat4[];
extern struct acpi_dmtable_info         acpi_dm_table_info_srat5[];
extern struct acpi_dmtable_info         acpi_dm_table_info_srat6[];
extern struct acpi_dmtable_info         acpi_dm_table_info_stao[];
extern struct acpi_dmtable_info         acpi_dm_table_info_stao_str[];
extern struct acpi_dmtable_info         acpi_dm_table_info_svkl[];
extern struct acpi_dmtable_info         acpi_dm_table_info_svkl0[];
extern struct acpi_dmtable_info         acpi_dm_table_info_tcpa_hdr[];
extern struct acpi_dmtable_info         acpi_dm_table_info_tcpa_client[];
extern struct acpi_dmtable_info         acpi_dm_table_info_tcpa_server[];
extern struct acpi_dmtable_info         acpi_dm_table_info_tdel[];
extern struct acpi_dmtable_info         acpi_dm_table_info_tpm2[];
extern struct acpi_dmtable_info         acpi_dm_table_info_tpm2a[];
extern struct acpi_dmtable_info         acpi_dm_table_info_tpm211[];
extern struct acpi_dmtable_info         acpi_dm_table_info_tpm23[];
extern struct acpi_dmtable_info         acpi_dm_table_info_tpm23a[];
extern struct acpi_dmtable_info         acpi_dm_table_info_uefi[];
extern struct acpi_dmtable_info         acpi_dm_table_info_viot[];
extern struct acpi_dmtable_info         acpi_dm_table_info_viot_header[];
extern struct acpi_dmtable_info         acpi_dm_table_info_viot1[];
extern struct acpi_dmtable_info         acpi_dm_table_info_viot2[];
extern struct acpi_dmtable_info         acpi_dm_table_info_viot3[];
extern struct acpi_dmtable_info         acpi_dm_table_info_viot4[];
extern struct acpi_dmtable_info         acpi_dm_table_info_waet[];
extern struct acpi_dmtable_info         acpi_dm_table_info_wdat[];
extern struct acpi_dmtable_info         acpi_dm_table_info_wdat0[];
extern struct acpi_dmtable_info         acpi_dm_table_info_wddt[];
extern struct acpi_dmtable_info         acpi_dm_table_info_wdrt[];
extern struct acpi_dmtable_info         acpi_dm_table_info_wpbt[];
extern struct acpi_dmtable_info         acpi_dm_table_info_wpbt0[];
extern struct acpi_dmtable_info         acpi_dm_table_info_wsmt[];
extern struct acpi_dmtable_info         acpi_dm_table_info_xenv[];

extern struct acpi_dmtable_info         acpi_dm_table_info_generic[][2];

/*
 * dmtable and ahtable
 */
extern const struct acpi_dmtable_data   acpi_dm_table_data[];
extern const struct ah_table            acpi_gbl_supported_tables[];

u8
acpi_dm_generate_checksum (
	void                            *table,
	u32                             length,
	u8                              original_checksum);

const struct acpi_dmtable_data *
acpi_dm_get_table_data (
	char                            *signature);

void
acpi_dm_dump_data_table (
	struct acpi_table_header        *table);

acpi_status
acpi_dm_dump_table (
	u32                             table_length,
	u32                             table_offset,
	void                            *table,
	u32                             subtable_length,
	struct acpi_dmtable_info         *info);

void
acpi_dm_line_header (
	u32                             offset,
	u32                             byte_length,
	char                            *name);

void
acpi_dm_line_header2 (
	u32                             offset,
	u32                             byte_length,
	char                            *name,
	u32                             value);


/*
 * dmtbdump
 */
void
acpi_dm_dump_buffer (
	void                            *table,
	u32                             buffer_offset,
	u32                             length,
	u32                             absolute_offset,
	char                            *header);

void
acpi_dm_dump_unicode (
	void                            *table,
	u32                             buffer_offset,
	u32                             byte_length);

void
acpi_dm_dump_aest (
	struct acpi_table_header        *table);

void
acpi_dm_dump_apmt (
	struct acpi_table_header        *table);

void
acpi_dm_dump_asf (
	struct acpi_table_header        *table);

void
acpi_dm_dump_ccel (
	struct acpi_table_header        *table);

void
acpi_dm_dump_cdat (
	struct acpi_table_header        *table);

void
acpi_dm_dump_cedt (
	struct acpi_table_header        *table);

void
acpi_dm_dump_cpep (
	struct acpi_table_header        *table);

void
acpi_dm_dump_csrt (
	struct acpi_table_header        *table);

void
acpi_dm_dump_dbg2 (
	struct acpi_table_header        *table);

void
acpi_dm_dump_dmar (
	struct acpi_table_header        *table);

void
acpi_dm_dump_drtm (
	struct acpi_table_header        *table);

void
acpi_dm_dump_einj (
	struct acpi_table_header        *table);

void
acpi_dm_dump_erst (
	struct acpi_table_header        *table);

void
acpi_dm_dump_fadt (
	struct acpi_table_header        *table);

void
acpi_dm_dump_fpdt (
	struct acpi_table_header        *table);

void
acpi_dm_dump_gtdt (
	struct acpi_table_header        *table);

void
acpi_dm_dump_hest (
	struct acpi_table_header        *table);

void
acpi_dm_dump_hmat (
	struct acpi_table_header        *table);

void
acpi_dm_dump_iort (
	struct acpi_table_header        *table);

void
acpi_dm_dump_ivrs (
	struct acpi_table_header        *table);

void
acpi_dm_dump_lpit (
	struct acpi_table_header        *table);

void
acpi_dm_dump_madt (
	struct acpi_table_header        *table);

void
acpi_dm_dump_mcfg (
	struct acpi_table_header        *table);

void
acpi_dm_dump_mpst (
	struct acpi_table_header        *table);

void
acpi_dm_dump_msct (
	struct acpi_table_header        *table);

void
acpi_dm_dump_nfit (
	struct acpi_table_header        *table);

void
acpi_dm_dump_nhlt (
	struct acpi_table_header        *table);

void
acpi_dm_dump_pcct (
	struct acpi_table_header        *table);

void
acpi_dm_dump_pdtt (
	struct acpi_table_header        *table);

void
acpi_dm_dump_phat (
	struct acpi_table_header        *table);

void
acpi_dm_dump_pmtt (
	struct acpi_table_header        *table);

void
acpi_dm_dump_pptt (
	struct acpi_table_header        *table);

void
acpi_dm_dump_prmt (
	struct acpi_table_header        *table);

void
acpi_dm_dump_rgrt (
	struct acpi_table_header        *table);

u32
acpi_dm_dump_rsdp (
	struct acpi_table_header        *table);

void
acpi_dm_dump_rsdt (
	struct acpi_table_header        *table);

u32
acpi_dm_dump_s3pt (
	struct acpi_table_header        *table);

void
acpi_dm_dump_sdev (
	struct acpi_table_header        *table);

void
acpi_dm_dump_slic (
	struct acpi_table_header        *table);

void
acpi_dm_dump_slit (
	struct acpi_table_header        *table);

void
acpi_dm_dump_srat (
	struct acpi_table_header        *table);

void
acpi_dm_dump_stao (
	struct acpi_table_header        *table);

void
acpi_dm_dump_svkl (
	struct acpi_table_header        *table);

void
acpi_dm_dump_tcpa (
	struct acpi_table_header        *table);

void
acpi_dm_dump_tdel (
	struct acpi_table_header        *table);

void
acpi_dm_dump_tpm2 (
	struct acpi_table_header        *table);

void
acpi_dm_dump_viot (
	struct acpi_table_header        *table);

void
acpi_dm_dump_wdat (
	struct acpi_table_header        *table);

void
acpi_dm_dump_wpbt (
	struct acpi_table_header        *table);

void
acpi_dm_dump_xsdt (
	struct acpi_table_header        *table);


/*
 * dmwalk
 */
void
acpi_dm_disassemble (
	struct acpi_walk_state          *walk_state,
	union acpi_parse_object         *origin,
	u32                             num_opcodes);

void
acpi_dm_walk_parse_tree (
	union acpi_parse_object         *op,
	asl_walk_callback               descending_callback,
	asl_walk_callback               ascending_callback,
	void                            *context);


/*
 * dmopcode
 */
void
acpi_dm_disassemble_one_op (
	struct acpi_walk_state          *walk_state,
	struct acpi_op_walk_info        *info,
	union acpi_parse_object         *op);

u32
acpi_dm_list_type (
	union acpi_parse_object         *op);

void
acpi_dm_method_flags (
	union acpi_parse_object         *op);

void
acpi_dm_display_target_pathname (
	union acpi_parse_object         *op);

void
acpi_dm_notify_description (
	union acpi_parse_object         *op);

void
acpi_dm_predefined_description (
	union acpi_parse_object         *op);

void
acpi_dm_field_predefined_description (
	union acpi_parse_object         *op);

void
acpi_dm_field_flags (
	union acpi_parse_object         *op);

void
acpi_dm_address_space (
	u8                              space_id);

void
acpi_dm_region_flags (
	union acpi_parse_object         *op);

void
acpi_dm_match_op (
	union acpi_parse_object         *op);


/*
 * dmnames
 */
u32
acpi_dm_dump_name (
	u32                             name);

acpi_status
acpi_ps_display_object_pathname (
	struct acpi_walk_state          *walk_state,
	union acpi_parse_object         *op);

void
acpi_dm_namestring (
	char                            *name);


/*
 * dmbuffer
 */
void
acpi_dm_disasm_byte_list (
	u32                             level,
	u8                              *byte_data,
	u32                             byte_count);

void
acpi_dm_byte_list (
	struct acpi_op_walk_info        *info,
	union acpi_parse_object         *op);

void
acpi_dm_check_for_hardware_id (
	union acpi_parse_object         *op);

void
acpi_dm_decompress_eisa_id (
	u32                             encoded_id);

u8
acpi_dm_is_uuid_buffer (
	union acpi_parse_object         *op);

u8
acpi_dm_is_unicode_buffer (
	union acpi_parse_object         *op);

u8
acpi_dm_is_string_buffer (
	union acpi_parse_object         *op);

u8
acpi_dm_is_pld_buffer (
	union acpi_parse_object         *op);


/*
 * dmdeferred
 */
acpi_status
acpi_dm_parse_deferred_ops (
	union acpi_parse_object         *root);


/*
 * dmextern
 */
acpi_status
acpi_dm_add_to_external_file_list (
	char                            *path_list);

void
acpi_dm_clear_external_file_list (
	void);

void
acpi_dm_add_op_to_external_list (
	union acpi_parse_object         *op,
	char                            *path,
	u8                              type,
	u32                             value,
	u16                             flags);

void
acpi_dm_create_subobject_for_external (
	u8                              type,
	struct acpi_namespace_node      **node,
	u32                             value);

void
acpi_dm_add_node_to_external_list (
	struct acpi_namespace_node      *node,
	u8                              type,
	u32                             value,
	u16                             flags);

void
acpi_dm_add_external_list_to_namespace (
	void);

void
acpi_dm_add_one_external_to_namespace (
	char                            *path,
	u8                              type,
	u32                             value);

u32
acpi_dm_get_unresolved_external_method_count (
	void);

void
acpi_dm_clear_external_list (
	void);

void
acpi_dm_emit_externals (
	void);

void
acpi_dm_emit_external (
	union acpi_parse_object         *name_op,
	union acpi_parse_object         *type_op);

void
acpi_dm_unresolved_warning (
	u8                              type);

void
acpi_dm_get_externals_from_file (
	void);

void
acpi_dm_mark_external_conflict (
	struct acpi_namespace_node      *node);


/*
 * dmresrc
 */
void
acpi_dm_dump_integer8 (
	u8                              value,
	const char                      *name);

void
acpi_dm_dump_integer16 (
	u16                             value,
	const char                      *name);

void
acpi_dm_dump_integer32 (
	u32                             value,
	const char                      *name);

void
acpi_dm_dump_integer64 (
	u64                             value,
	const char                      *name);

void
acpi_dm_resource_template (
	struct acpi_op_walk_info        *info,
	union acpi_parse_object         *op,
	u8                              *byte_data,
	u32                             byte_count);

acpi_status
acpi_dm_is_resource_template (
	struct acpi_walk_state          *walk_state,
	union acpi_parse_object         *op);

void
acpi_dm_bit_list (
	u16                             mask);

void
acpi_dm_descriptor_name (
	void);


/*
 * dmresrcl
 */
void
acpi_dm_word_descriptor (
	struct acpi_op_walk_info        *info,
	union aml_resource              *resource,
	u32                             length,
	u32                             level);

void
acpi_dm_dword_descriptor (
	struct acpi_op_walk_info        *info,
	union aml_resource              *resource,
	u32                             length,
	u32                             level);

void
acpi_dm_extended_descriptor (
	struct acpi_op_walk_info        *info,
	union aml_resource              *resource,
	u32                             length,
	u32                             level);

void
acpi_dm_qword_descriptor (
	struct acpi_op_walk_info        *info,
	union aml_resource              *resource,
	u32                             length,
	u32                             level);

void
acpi_dm_memory24_descriptor (
	struct acpi_op_walk_info        *info,
	union aml_resource              *resource,
	u32                             length,
	u32                             level);

void
acpi_dm_memory32_descriptor (
	struct acpi_op_walk_info        *info,
	union aml_resource              *resource,
	u32                             length,
	u32                             level);

void
acpi_dm_fixed_memory32_descriptor (
	struct acpi_op_walk_info        *info,
	union aml_resource              *resource,
	u32                             length,
	u32                             level);

void
acpi_dm_generic_register_descriptor (
	struct acpi_op_walk_info        *info,
	union aml_resource              *resource,
	u32                             length,
	u32                             level);

void
acpi_dm_interrupt_descriptor (
	struct acpi_op_walk_info        *info,
	union aml_resource              *resource,
	u32                             length,
	u32                             level);

void
acpi_dm_vendor_large_descriptor (
	struct acpi_op_walk_info        *info,
	union aml_resource              *resource,
	u32                             length,
	u32                             level);

void
acpi_dm_gpio_descriptor (
	struct acpi_op_walk_info        *info,
	union aml_resource              *resource,
	u32                             length,
	u32                             level);

void
acpi_dm_pin_function_descriptor (
	struct acpi_op_walk_info        *info,
	union aml_resource              *resource,
	u32                             length,
	u32                             level);

void
acpi_dm_pin_config_descriptor (
	struct acpi_op_walk_info        *info,
	union aml_resource              *resource,
	u32                             length,
	u32                             level);

void
acpi_dm_pin_group_descriptor (
	struct acpi_op_walk_info        *info,
	union aml_resource              *resource,
	u32                             length,
	u32                             level);

void
acpi_dm_pin_group_function_descriptor (
	struct acpi_op_walk_info        *info,
	union aml_resource              *resource,
	u32                             length,
	u32                             level);

void
acpi_dm_pin_group_config_descriptor (
	struct acpi_op_walk_info        *info,
	union aml_resource              *resource,
	u32                             length,
	u32                             level);

void
acpi_dm_serial_bus_descriptor (
	struct acpi_op_walk_info        *info,
	union aml_resource              *resource,
	u32                             length,
	u32                             level);

void
acpi_dm_vendor_common (
	const char                      *name,
	u8                              *byte_data,
	u32                             length,
	u32                             level);


/*
 * dmresrcs
 */
void
acpi_dm_irq_descriptor (
	struct acpi_op_walk_info        *info,
	union aml_resource              *resource,
	u32                             length,
	u32                             level);

void
acpi_dm_dma_descriptor (
	struct acpi_op_walk_info        *info,
	union aml_resource              *resource,
	u32                             length,
	u32                             level);

void
acpi_dm_fixed_dma_descriptor (
	struct acpi_op_walk_info        *info,
	union aml_resource              *resource,
	u32                             length,
	u32                             level);

void
acpi_dm_io_descriptor (
	struct acpi_op_walk_info        *info,
	union aml_resource              *resource,
	u32                             length,
	u32                             level);

void
acpi_dm_fixed_io_descriptor (
	struct acpi_op_walk_info        *info,
	union aml_resource              *resource,
	u32                             length,
	u32                             level);

void
acpi_dm_start_dependent_descriptor (
	struct acpi_op_walk_info        *info,
	union aml_resource              *resource,
	u32                             length,
	u32                             level);

void
acpi_dm_end_dependent_descriptor (
	struct acpi_op_walk_info        *info,
	union aml_resource              *resource,
	u32                             length,
	u32                             level);

void
acpi_dm_vendor_small_descriptor (
	struct acpi_op_walk_info        *info,
	union aml_resource              *resource,
	u32                             length,
	u32                             level);


/*
 * dmutils
 */
void
acpi_dm_decode_attribute (
	u8                              attribute);

void
acpi_dm_indent (
	u32                             level);

u8
acpi_dm_comma_if_list_member (
	union acpi_parse_object         *op);

void
acpi_dm_comma_if_field_member (
	union acpi_parse_object         *op);


/*
 * dmrestag
 */
void
acpi_dm_find_resources (
	union acpi_parse_object         *root);

void
acpi_dm_check_resource_reference (
	union acpi_parse_object         *op,
	struct acpi_walk_state          *walk_state);


/*
 * dmcstyle
 */
u8
acpi_dm_check_for_symbolic_opcode (
	union acpi_parse_object         *op,
	struct acpi_op_walk_info        *info);

void
acpi_dm_close_operator (
	union acpi_parse_object         *op);


/*
 * dmtables
 */
acpi_status
acpi_dm_process_switch (
	union acpi_parse_object         *op);

void
acpi_dm_clear_temp_list(
	void);

/*
 * dmtables
 */
void
ad_disassembler_header (
	char                            *filename,
	u8                              table_type);

#define ACPI_IS_AML_TABLE   0
#define ACPI_IS_DATA_TABLE  1


/*
 * adisasm
 */
acpi_status
ad_aml_disassemble (
	u8                              out_to_file,
	char                            *filename,
	char                            *prefix,
	char                            **out_filename);

acpi_status
ad_get_local_tables (
	void);

acpi_status
ad_parse_table (
	struct acpi_table_header        *table,
	acpi_owner_id                   *owner_id,
	u8                              load_table,
	u8                              external);

acpi_status
ad_display_tables (
	char                            *filename,
	struct acpi_table_header        *table);

acpi_status
ad_display_statistics (
	void);


/*
 * dmwalk
 */
u32
acpi_dm_block_type (
	union acpi_parse_object         *op);


#endif  /* __ACDISASM_H__ */
