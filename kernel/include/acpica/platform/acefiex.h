/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/******************************************************************************
 *
 * Name: acefiex.h - Extra OS specific defines, etc. for EFI
 *
 * Copyright (C) 2000 - 2022, Intel Corp.
 *
 *****************************************************************************/


#ifndef __ACEFIEX_H__
#define __ACEFIEX_H__


#ifndef ACPI_USE_SYSTEM_CLIBRARY

typedef signed char                             int8_t;
typedef short int                               int16_t;
typedef int                                     int32_t;
typedef unsigned char                           uint8_t;
typedef unsigned short int                      uint16_t;
typedef unsigned int                            uint32_t;
typedef COMPILER_DEPENDENT_INT64        int64_t;
typedef COMPILER_DEPENDENT_UINT64       uint64_t;

#endif /* ACPI_USE_SYSTEM_CLIBRARY */

#define ACPI_EFI_ERROR(a)               (((INTN) a) < 0)
#define ACPI_EFI_SUCCESS                0
#define ACPI_EFI_LOAD_ERROR             ACPI_EFI_ERR(1)
#define ACPI_EFI_INVALID_PARAMETER      ACPI_EFI_ERR(2)
#define ACPI_EFI_UNSUPPORTED            ACPI_EFI_ERR(3)
#define ACPI_EFI_BAD_BUFFER_SIZE        ACPI_EFI_ERR(4)
#define ACPI_EFI_BUFFER_TOO_SMALL       ACPI_EFI_ERR(5)
#define ACPI_EFI_NOT_READY              ACPI_EFI_ERR(6)
#define ACPI_EFI_DEVICE_ERROR           ACPI_EFI_ERR(7)
#define ACPI_EFI_WRITE_PROTECTED        ACPI_EFI_ERR(8)
#define ACPI_EFI_OUT_OF_RESOURCES       ACPI_EFI_ERR(9)
#define ACPI_EFI_VOLUME_CORRUPTED       ACPI_EFI_ERR(10)
#define ACPI_EFI_VOLUME_FULL            ACPI_EFI_ERR(11)
#define ACPI_EFI_NO_MEDIA               ACPI_EFI_ERR(12)
#define ACPI_EFI_MEDIA_CHANGED          ACPI_EFI_ERR(13)
#define ACPI_EFI_NOT_FOUND              ACPI_EFI_ERR(14)
#define ACPI_EFI_ACCESS_DENIED          ACPI_EFI_ERR(15)
#define ACPI_EFI_NO_RESPONSE            ACPI_EFI_ERR(16)
#define ACPI_EFI_NO_MAPPING             ACPI_EFI_ERR(17)
#define ACPI_EFI_TIMEOUT                ACPI_EFI_ERR(18)
#define ACPI_EFI_NOT_STARTED            ACPI_EFI_ERR(19)
#define ACPI_EFI_ALREADY_STARTED        ACPI_EFI_ERR(20)
#define ACPI_EFI_ABORTED                ACPI_EFI_ERR(21)
#define ACPI_EFI_PROTOCOL_ERROR         ACPI_EFI_ERR(24)


typedef UINTN ACPI_EFI_STATUS;
typedef VOID *ACPI_EFI_HANDLE;
typedef VOID *ACPI_EFI_EVENT;

typedef struct {
	u32  data1;
	u16  data2;
	u16  data3;
	u8   data4[8];
} ACPI_EFI_GUID;

typedef struct {
	u16 year;       /* 1998 - 20XX */
	u8  month;      /* 1 - 12 */
	u8  day;        /* 1 - 31 */
	u8  hour;       /* 0 - 23 */
	u8  minute;     /* 0 - 59 */
	u8  second;     /* 0 - 59 */
	u8  pad1;
	u32 nanosecond; /* 0 - 999,999,999 */
	s16  time_zone;  /* -1440 to 1440 or 2047 */
	u8  daylight;
	u8  pad2;
} ACPI_EFI_TIME;

struct _ACPI_EFI_DEVICE_PATH {
		u8                                      type;
		u8                                      sub_type;
		u8                                      length[2];
};

typedef u64                     ACPI_EFI_PHYSICAL_ADDRESS;
typedef u64                     ACPI_EFI_VIRTUAL_ADDRESS;

typedef enum {
	acpi_efi_allocate_any_pages,
	acpi_efi_allocate_max_address,
	acpi_efi_allocate_address,
	acpi_efi_max_allocate_type
} ACPI_EFI_ALLOCATE_TYPE;

typedef enum {
	acpi_efi_reserved_memory_type,
	acpi_efi_loader_code,
	acpi_efi_loader_data,
	acpi_efi_boot_services_code,
	acpi_efi_boot_services_data,
	acpi_efi_runtime_services_code,
	acpi_efi_runtime_services_data,
	acpi_efi_conventional_memory,
	acpi_efi_unusable_memory,
	acpi_efi_ACPireclaim_memory,
	acpi_efi_ACPimemory_NVS,
	acpi_efi_memory_mapped_IO,
	acpi_efi_memory_mapped_Ioport_space,
	acpi_efi_pal_code,
	acpi_efi_max_memory_type
} ACPI_EFI_MEMORY_TYPE;

/* possible caching types for the memory range */
#define ACPI_EFI_MEMORY_UC      0x0000000000000001
#define ACPI_EFI_MEMORY_WC      0x0000000000000002
#define ACPI_EFI_MEMORY_WT      0x0000000000000004
#define ACPI_EFI_MEMORY_WB      0x0000000000000008
#define ACPI_EFI_MEMORY_UCE     0x0000000000000010

/* physical memory protection on range */
#define ACPI_EFI_MEMORY_WP      0x0000000000001000
#define ACPI_EFI_MEMORY_RP      0x0000000000002000
#define ACPI_EFI_MEMORY_XP      0x0000000000004000

/* range requires a runtime mapping */
#define ACPI_EFI_MEMORY_RUNTIME 0x8000000000000000

#define ACPI_EFI_MEMORY_DESCRIPTOR_VERSION  1
typedef struct {
	u32                                     type;
	u32                                     pad;
	ACPI_EFI_PHYSICAL_ADDRESS       physical_start;
	ACPI_EFI_VIRTUAL_ADDRESS        virtual_start;
	u64                                     number_of_pages;
	u64                                     attribute;
} ACPI_EFI_MEMORY_DESCRIPTOR;

struct _ACPI_EFI_TABLE_HEARDER {
	u64                                 signature;
	u32                                 revision;
	u32                                 header_size;
	u32                                 CRC32;
	u32                                 reserved;
};

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_UNKNOWN_INTERFACE) (
	void);


/*
 * Text output protocol
 */
#define ACPI_SIMPLE_TEXT_OUTPUT_PROTOCOL \
	{ 0x387477c2, 0x69c7, 0x11d2, {0x8e, 0x39, 0x0, 0xa0, 0xc9, 0x69, 0x72, 0x3b} }

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_TEXT_RESET) (
	struct _ACPI_SIMPLE_TEXT_OUTPUT_INTERFACE   *this,
	u8                                                  extended_verification);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_TEXT_OUTPUT_STRING) (
	struct _ACPI_SIMPLE_TEXT_OUTPUT_INTERFACE   *this,
	CHAR16                                      *string);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_TEXT_TEST_STRING) (
	struct _ACPI_SIMPLE_TEXT_OUTPUT_INTERFACE   *this,
	CHAR16                                      *string);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_TEXT_QUERY_MODE) (
	struct _ACPI_SIMPLE_TEXT_OUTPUT_INTERFACE   *this,
	UINTN                                       mode_number,
	UINTN                                       *columns,
	UINTN                                       *rows);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_TEXT_SET_MODE) (
	struct _ACPI_SIMPLE_TEXT_OUTPUT_INTERFACE   *this,
	UINTN                                       mode_number);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_TEXT_SET_ATTRIBUTE) (
	struct _ACPI_SIMPLE_TEXT_OUTPUT_INTERFACE   *this,
	UINTN                                       attribute);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_TEXT_CLEAR_SCREEN) (
	struct _ACPI_SIMPLE_TEXT_OUTPUT_INTERFACE   *this);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_TEXT_SET_CURSOR_POSITION) (
	struct _ACPI_SIMPLE_TEXT_OUTPUT_INTERFACE   *this,
	UINTN                                       column,
	UINTN                                       row);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_TEXT_ENABLE_CURSOR) (
	struct _ACPI_SIMPLE_TEXT_OUTPUT_INTERFACE   *this,
	u8                                                  enable);

typedef struct {
	s32                                     max_mode;
	s32                                     mode;
	s32                                     attribute;
	s32                                     cursor_column;
	s32                                     cursor_row;
	u8                                      cursor_visible;
} ACPI_SIMPLE_TEXT_OUTPUT_MODE;

struct _ACPI_SIMPLE_TEXT_OUTPUT_INTERFACE {
	ACPI_EFI_TEXT_RESET                 reset;

	ACPI_EFI_TEXT_OUTPUT_STRING         output_string;
	ACPI_EFI_TEXT_TEST_STRING           test_string;

	ACPI_EFI_TEXT_QUERY_MODE            query_mode;
	ACPI_EFI_TEXT_SET_MODE              set_mode;
	ACPI_EFI_TEXT_SET_ATTRIBUTE         set_attribute;

	ACPI_EFI_TEXT_CLEAR_SCREEN          clear_screen;
	ACPI_EFI_TEXT_SET_CURSOR_POSITION   set_cursor_position;
	ACPI_EFI_TEXT_ENABLE_CURSOR         enable_cursor;

	ACPI_SIMPLE_TEXT_OUTPUT_MODE        *mode;
};

/*
 * Text input protocol
 */
#define ACPI_SIMPLE_TEXT_INPUT_PROTOCOL  \
	{ 0x387477c1, 0x69c7, 0x11d2, {0x8e, 0x39, 0x0, 0xa0, 0xc9, 0x69, 0x72, 0x3b} }

typedef struct {
	u16                                         scan_code;
	CHAR16                              unicode_char;
} ACPI_EFI_INPUT_KEY;

/*
 * Baseline unicode control chars
 */
#define CHAR_NULL                       0x0000
#define CHAR_BACKSPACE                  0x0008
#define CHAR_TAB                        0x0009
#define CHAR_LINEFEED                   0x000A
#define CHAR_CARRIAGE_RETURN            0x000D

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_INPUT_RESET) (
	struct _ACPI_SIMPLE_INPUT_INTERFACE         *this,
	u8                                                  extended_verification);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_INPUT_READ_KEY) (
	struct _ACPI_SIMPLE_INPUT_INTERFACE         *this,
	ACPI_EFI_INPUT_KEY                          *key);

struct _ACPI_SIMPLE_INPUT_INTERFACE {
	ACPI_EFI_INPUT_RESET                    reset;
	ACPI_EFI_INPUT_READ_KEY                 read_key_stroke;
	ACPI_EFI_EVENT                          wait_for_key;
};


/*
 * Simple file system protocol
 */
#define ACPI_SIMPLE_FILE_SYSTEM_PROTOCOL \
	{ 0x964e5b22, 0x6459, 0x11d2, {0x8e, 0x39, 0x0, 0xa0, 0xc9, 0x69, 0x72, 0x3b} }

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_VOLUME_OPEN) (
	struct _ACPI_EFI_FILE_IO_INTERFACE          *this,
	struct _ACPI_EFI_FILE_HANDLE                **root);

#define ACPI_EFI_FILE_IO_INTERFACE_REVISION     0x00010000

struct _ACPI_EFI_FILE_IO_INTERFACE {
	u64                             revision;
	ACPI_EFI_VOLUME_OPEN    open_volume;
};

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_FILE_OPEN) (
	struct _ACPI_EFI_FILE_HANDLE                *file,
	struct _ACPI_EFI_FILE_HANDLE                **new_handle,
	CHAR16                                      *file_name,
	u64                                                 open_mode,
	u64                                                 attributes);

/* Values for open_mode used above */

#define ACPI_EFI_FILE_MODE_READ     0x0000000000000001
#define ACPI_EFI_FILE_MODE_WRITE    0x0000000000000002
#define ACPI_EFI_FILE_MODE_CREATE   0x8000000000000000

/* Values for Attribute used above */

#define ACPI_EFI_FILE_READ_ONLY     0x0000000000000001
#define ACPI_EFI_FILE_HIDDEN        0x0000000000000002
#define ACPI_EFI_FILE_SYSTEM        0x0000000000000004
#define ACPI_EFI_FILE_RESERVIED     0x0000000000000008
#define ACPI_EFI_FILE_DIRECTORY     0x0000000000000010
#define ACPI_EFI_FILE_ARCHIVE       0x0000000000000020
#define ACPI_EFI_FILE_VALID_ATTR    0x0000000000000037

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_FILE_CLOSE) (
	struct _ACPI_EFI_FILE_HANDLE                *file);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_FILE_DELETE) (
	struct _ACPI_EFI_FILE_HANDLE                *file);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_FILE_READ) (
	struct _ACPI_EFI_FILE_HANDLE                *file,
	UINTN                                       *buffer_size,
	VOID                                        *buffer);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_FILE_WRITE) (
	struct _ACPI_EFI_FILE_HANDLE                *file,
	UINTN                                       *buffer_size,
	VOID                                        *buffer);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_FILE_SET_POSITION) (
	struct _ACPI_EFI_FILE_HANDLE                *file,
	u64                                                 position);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_FILE_GET_POSITION) (
	struct _ACPI_EFI_FILE_HANDLE                *file,
	u64                                                 *position);

#define ACPI_EFI_FILE_INFO_ID \
	{ 0x9576e92, 0x6d3f, 0x11d2, {0x8e, 0x39, 0x0, 0xa0, 0xc9, 0x69, 0x72, 0x3b} }

typedef struct {
	u64 size;
	u64 file_size;
	u64 physical_size;
	ACPI_EFI_TIME create_time;
	ACPI_EFI_TIME last_access_time;
	ACPI_EFI_TIME modification_time;
	u64 attribute;
	CHAR16 file_name[1];
} ACPI_EFI_FILE_INFO;

#define SIZE_OF_ACPI_EFI_FILE_INFO  ACPI_OFFSET(ACPI_EFI_FILE_INFO, file_name)

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_FILE_GET_INFO) (
	struct _ACPI_EFI_FILE_HANDLE                *file,
	ACPI_EFI_GUID                               *information_type,
	UINTN                                       *buffer_size,
	VOID                                        *buffer);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_FILE_SET_INFO) (
	struct _ACPI_EFI_FILE_HANDLE                *file,
	ACPI_EFI_GUID                               *information_type,
	UINTN                                       buffer_size,
	VOID                                        *buffer);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_FILE_FLUSH) (
	struct _ACPI_EFI_FILE_HANDLE                *file);


#define ACPI_EFI_FILE_HANDLE_REVISION           0x00010000

struct _ACPI_EFI_FILE_HANDLE {
	u64                                 revision;
	ACPI_EFI_FILE_OPEN          open;
	ACPI_EFI_FILE_CLOSE         close;
	ACPI_EFI_FILE_DELETE        delete;
	ACPI_EFI_FILE_READ          read;
	ACPI_EFI_FILE_WRITE         write;
	ACPI_EFI_FILE_GET_POSITION  get_position;
	ACPI_EFI_FILE_SET_POSITION  set_position;
	ACPI_EFI_FILE_GET_INFO      get_info;
	ACPI_EFI_FILE_SET_INFO      set_info;
	ACPI_EFI_FILE_FLUSH         flush;
};


/*
 * Loaded image protocol
 */
#define ACPI_EFI_LOADED_IMAGE_PROTOCOL \
	{ 0x5B1B31A1, 0x9562, 0x11d2, {0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B} }

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_IMAGE_ENTRY_POINT) (
	ACPI_EFI_HANDLE                         image_handle,
	struct _ACPI_EFI_SYSTEM_TABLE           *system_table);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_IMAGE_LOAD) (
	u8                                      boot_policy,
	ACPI_EFI_HANDLE                 parent_image_handle,
	ACPI_EFI_DEVICE_PATH            *file_path,
	VOID                            *source_buffer,
	UINTN                           source_size,
	ACPI_EFI_HANDLE                 *image_handle);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_IMAGE_START) (
	ACPI_EFI_HANDLE                 image_handle,
	UINTN                           *exit_data_size,
	CHAR16                          **exit_data);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_EXIT) (
	ACPI_EFI_HANDLE                 image_handle,
	ACPI_EFI_STATUS                 exit_status,
	UINTN                           exit_data_size,
	CHAR16                          *exit_data);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_IMAGE_UNLOAD) (
	ACPI_EFI_HANDLE                 image_handle);


typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_STALL) (
	UINTN                           microseconds);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_SET_WATCHDOG_TIMER) (
	UINTN                           timeout,
	u64                                     watchdog_code,
	UINTN                           data_size,
	CHAR16                          *watchdog_data);


#define EFI_IMAGE_INFORMATION_REVISION      0x1000
typedef struct {
	u32                                     revision;
	ACPI_EFI_HANDLE                 parent_handle;
	struct _ACPI_EFI_SYSTEM_TABLE   *system_table;
	ACPI_EFI_HANDLE                 device_handle;
	ACPI_EFI_DEVICE_PATH            *file_path;
	VOID                            *reserved;
	u32                                     load_options_size;
	VOID                            *load_options;
	VOID                            *image_base;
	u64                                     image_size;
	ACPI_EFI_MEMORY_TYPE            image_code_type;
	ACPI_EFI_MEMORY_TYPE            image_data_type;
	ACPI_EFI_IMAGE_UNLOAD           unload;

} ACPI_EFI_LOADED_IMAGE;


/*
 * EFI Memory
 */
typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_ALLOCATE_PAGES) (
	ACPI_EFI_ALLOCATE_TYPE          type,
	ACPI_EFI_MEMORY_TYPE            memory_type,
	UINTN                           no_pages,
	ACPI_EFI_PHYSICAL_ADDRESS       *memory);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_FREE_PAGES) (
	ACPI_EFI_PHYSICAL_ADDRESS       memory,
	UINTN                           no_pages);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_GET_MEMORY_MAP) (
	UINTN                           *memory_map_size,
	ACPI_EFI_MEMORY_DESCRIPTOR      *memory_map,
	UINTN                           *map_key,
	UINTN                           *descriptor_size,
	u32                                     *descriptor_version);

#define next_memory_descriptor(ptr,size) ((ACPI_EFI_MEMORY_DESCRIPTOR *) (((u8 *) ptr) + size))

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_ALLOCATE_POOL) (
	ACPI_EFI_MEMORY_TYPE            pool_type,
	UINTN                           size,
	VOID                            **buffer);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_FREE_POOL) (
	VOID                            *buffer);


/*
 * EFI Time
 */
typedef struct {
	u32 resolution;
	u32 accuracy;
	u8 sets_to_zero;
} ACPI_EFI_TIME_CAPABILITIES;

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_GET_TIME) (
	ACPI_EFI_TIME                   *time,
	ACPI_EFI_TIME_CAPABILITIES      *capabilities);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_SET_TIME) (
	ACPI_EFI_TIME                   *time);


/*
 * Protocol handler functions
 */
typedef enum {
	ACPI_EFI_NATIVE_INTERFACE,
	ACPI_EFI_PCODE_INTERFACE
} ACPI_EFI_INTERFACE_TYPE;

typedef enum {
	acpi_efi_all_handles,
	acpi_efi_by_register_notify,
	acpi_efi_by_protocol
} ACPI_EFI_LOCATE_SEARCH_TYPE;

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_INSTALL_PROTOCOL_INTERFACE) (
	ACPI_EFI_HANDLE                 *handle,
	ACPI_EFI_GUID                   *protocol,
	ACPI_EFI_INTERFACE_TYPE         interface_type,
	VOID                            *interface);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_REINSTALL_PROTOCOL_INTERFACE) (
	ACPI_EFI_HANDLE                 handle,
	ACPI_EFI_GUID                   *protocol,
	VOID                            *old_interface,
	VOID                            *new_interface);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_UNINSTALL_PROTOCOL_INTERFACE) (
	ACPI_EFI_HANDLE                 handle,
	ACPI_EFI_GUID                   *protocol,
	VOID                            *interface);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_HANDLE_PROTOCOL) (
	ACPI_EFI_HANDLE                 handle,
	ACPI_EFI_GUID                   *protocol,
	VOID                            **interface);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_REGISTER_PROTOCOL_NOTIFY) (
	ACPI_EFI_GUID                   *protocol,
	ACPI_EFI_EVENT                  event,
	VOID                            **registration);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_LOCATE_HANDLE) (
	ACPI_EFI_LOCATE_SEARCH_TYPE     search_type,
	ACPI_EFI_GUID                   *protocol,
	VOID                            *search_key,
	UINTN                           *buffer_size,
	ACPI_EFI_HANDLE                 *buffer);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_LOCATE_DEVICE_PATH) (
	ACPI_EFI_GUID                   *protocol,
	ACPI_EFI_DEVICE_PATH            **device_path,
	ACPI_EFI_HANDLE                 *device);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_INSTALL_CONFIGURATION_TABLE) (
	ACPI_EFI_GUID                   *guid,
	VOID                            *table);

#define ACPI_EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL  0x00000001
#define ACPI_EFI_OPEN_PROTOCOL_GET_PROTOCOL        0x00000002
#define ACPI_EFI_OPEN_PROTOCOL_TEST_PROTOCOL       0x00000004
#define ACPI_EFI_OPEN_PROTOCOL_BY_CHILD_CONTROLLER 0x00000008
#define ACPI_EFI_OPEN_PROTOCOL_BY_DRIVER           0x00000010
#define ACPI_EFI_OPEN_PROTOCOL_EXCLUSIVE           0x00000020

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_OPEN_PROTOCOL) (
	ACPI_EFI_HANDLE                 handle,
	ACPI_EFI_GUID                   *protocol,
	VOID                            **interface,
	ACPI_EFI_HANDLE                 agent_handle,
	ACPI_EFI_HANDLE                 controller_handle,
	u32                                     attributes);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_CLOSE_PROTOCOL) (
	ACPI_EFI_HANDLE                 handle,
	ACPI_EFI_GUID                   *protocol,
	ACPI_EFI_HANDLE                 agent_handle,
	ACPI_EFI_HANDLE                 controller_handle);

typedef struct {
	ACPI_EFI_HANDLE                 agent_handle;
	ACPI_EFI_HANDLE                 controller_handle;
	u32                                     attributes;
	u32                                     open_count;
} ACPI_EFI_OPEN_PROTOCOL_INFORMATION_ENTRY;

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_OPEN_PROTOCOL_INFORMATION) (
	ACPI_EFI_HANDLE                 handle,
	ACPI_EFI_GUID                   *protocol,
	ACPI_EFI_OPEN_PROTOCOL_INFORMATION_ENTRY **entry_buffer,
	UINTN                           *entry_count);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_PROTOCOLS_PER_HANDLE) (
	ACPI_EFI_HANDLE                 handle,
	ACPI_EFI_GUID                   ***protocol_buffer,
	UINTN                           *protocol_buffer_count);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_LOCATE_HANDLE_BUFFER) (
	ACPI_EFI_LOCATE_SEARCH_TYPE     search_type,
	ACPI_EFI_GUID                   *protocol,
	VOID                            *search_key,
	UINTN                           *no_handles,
	ACPI_EFI_HANDLE                 **buffer);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_LOCATE_PROTOCOL) (
	ACPI_EFI_GUID                   *protocol,
	VOID                            *registration,
	VOID                            **interface);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_INSTALL_MULTIPLE_PROTOCOL_INTERFACES) (
	ACPI_EFI_HANDLE                 *handle,
	...);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_UNINSTALL_MULTIPLE_PROTOCOL_INTERFACES) (
	ACPI_EFI_HANDLE                 handle,
	...);

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_CALCULATE_CRC32) (
	VOID                            *data,
	UINTN                           data_size,
	u32                                     *crc32);

typedef
VOID
(ACPI_EFI_API *ACPI_EFI_COPY_MEM) (
	VOID                            *destination,
	VOID                            *source,
	UINTN                           length);

typedef
VOID
(ACPI_EFI_API *ACPI_EFI_SET_MEM) (
	VOID                            *buffer,
	UINTN                           size,
	u8                                      value);

/*
 * EFI Boot Services Table
 */
#define ACPI_EFI_BOOT_SERVICES_SIGNATURE 0x56524553544f4f42
#define ACPI_EFI_BOOT_SERVICES_REVISION  (ACPI_EFI_SPECIFICATION_MAJOR_REVISION<<16) | (ACPI_EFI_SPECIFICATION_MINOR_REVISION)

struct _ACPI_EFI_BOOT_SERVICES {
	ACPI_EFI_TABLE_HEADER               hdr;

#if 0
	ACPI_EFI_RAISE_TPL                  raise_TPL;
	ACPI_EFI_RESTORE_TPL                restore_TPL;
#else
	ACPI_EFI_UNKNOWN_INTERFACE          raise_TPL;
	ACPI_EFI_UNKNOWN_INTERFACE          restore_TPL;
#endif

	ACPI_EFI_ALLOCATE_PAGES             allocate_pages;
	ACPI_EFI_FREE_PAGES                 free_pages;
	ACPI_EFI_GET_MEMORY_MAP             get_memory_map;
	ACPI_EFI_ALLOCATE_POOL              allocate_pool;
	ACPI_EFI_FREE_POOL                  free_pool;

#if 0
	ACPI_EFI_CREATE_EVENT               create_event;
	ACPI_EFI_SET_TIMER                  set_timer;
	ACPI_EFI_WAIT_FOR_EVENT             wait_for_event;
	ACPI_EFI_SIGNAL_EVENT               signal_event;
	ACPI_EFI_CLOSE_EVENT                close_event;
	ACPI_EFI_CHECK_EVENT                check_event;
#else
	ACPI_EFI_UNKNOWN_INTERFACE          create_event;
	ACPI_EFI_UNKNOWN_INTERFACE          set_timer;
	ACPI_EFI_UNKNOWN_INTERFACE          wait_for_event;
	ACPI_EFI_UNKNOWN_INTERFACE          signal_event;
	ACPI_EFI_UNKNOWN_INTERFACE          close_event;
	ACPI_EFI_UNKNOWN_INTERFACE          check_event;
#endif

	ACPI_EFI_INSTALL_PROTOCOL_INTERFACE install_protocol_interface;
	ACPI_EFI_REINSTALL_PROTOCOL_INTERFACE reinstall_protocol_interface;
	ACPI_EFI_UNINSTALL_PROTOCOL_INTERFACE uninstall_protocol_interface;
	ACPI_EFI_HANDLE_PROTOCOL            handle_protocol;
	ACPI_EFI_HANDLE_PROTOCOL            Pchandle_protocol;
	ACPI_EFI_REGISTER_PROTOCOL_NOTIFY   register_protocol_notify;
	ACPI_EFI_LOCATE_HANDLE              locate_handle;
	ACPI_EFI_LOCATE_DEVICE_PATH         locate_device_path;
	ACPI_EFI_INSTALL_CONFIGURATION_TABLE install_configuration_table;

	ACPI_EFI_IMAGE_LOAD                 load_image;
	ACPI_EFI_IMAGE_START                start_image;
	ACPI_EFI_EXIT                       exit;
	ACPI_EFI_IMAGE_UNLOAD               unload_image;

#if 0
	ACPI_EFI_EXIT_BOOT_SERVICES         exit_boot_services;
	ACPI_EFI_GET_NEXT_MONOTONIC_COUNT   get_next_monotonic_count;
#else
	ACPI_EFI_UNKNOWN_INTERFACE          exit_boot_services;
	ACPI_EFI_UNKNOWN_INTERFACE          get_next_monotonic_count;
#endif
	ACPI_EFI_STALL                      stall;
	ACPI_EFI_SET_WATCHDOG_TIMER         set_watchdog_timer;

#if 0
	ACPI_EFI_CONNECT_CONTROLLER         connect_controller;
	ACPI_EFI_DISCONNECT_CONTROLLER      disconnect_controller;
#else
	ACPI_EFI_UNKNOWN_INTERFACE          connect_controller;
	ACPI_EFI_UNKNOWN_INTERFACE          disconnect_controller;
#endif

	ACPI_EFI_OPEN_PROTOCOL              open_protocol;
	ACPI_EFI_CLOSE_PROTOCOL             close_protocol;
	ACPI_EFI_OPEN_PROTOCOL_INFORMATION  open_protocol_information;
	ACPI_EFI_PROTOCOLS_PER_HANDLE       protocols_per_handle;
	ACPI_EFI_LOCATE_HANDLE_BUFFER       locate_handle_buffer;
	ACPI_EFI_LOCATE_PROTOCOL            locate_protocol;
	ACPI_EFI_INSTALL_MULTIPLE_PROTOCOL_INTERFACES install_multiple_protocol_interfaces;
	ACPI_EFI_UNINSTALL_MULTIPLE_PROTOCOL_INTERFACES uninstall_multiple_protocol_interfaces;

	ACPI_EFI_CALCULATE_CRC32        calculate_crc32;

	ACPI_EFI_COPY_MEM               copy_mem;
	ACPI_EFI_SET_MEM                set_mem;

#if 0
	ACPI_EFI_CREATE_EVENT_EX        create_event_ex;
#else
	ACPI_EFI_UNKNOWN_INTERFACE      create_event_ex;
#endif
};


/*
 * EFI Runtime Services Table
 */
#define ACPI_EFI_RUNTIME_SERVICES_SIGNATURE 0x56524553544e5552
#define ACPI_EFI_RUNTIME_SERVICES_REVISION  (EFI_SPECIFICATION_MAJOR_REVISION<<16) | (EFI_SPECIFICATION_MINOR_REVISION)

struct _ACPI_EFI_RUNTIME_SERVICES {
	ACPI_EFI_TABLE_HEADER               hdr;

	ACPI_EFI_GET_TIME                   get_time;
	ACPI_EFI_SET_TIME                   set_time;
#if 0
	ACPI_EFI_GET_WAKEUP_TIME            get_wakeup_time;
	ACPI_EFI_SET_WAKEUP_TIME            set_wakeup_time;
#else
	ACPI_EFI_UNKNOWN_INTERFACE          get_wakeup_time;
	ACPI_EFI_UNKNOWN_INTERFACE          set_wakeup_time;
#endif

#if 0
	ACPI_EFI_SET_VIRTUAL_ADDRESS_MAP    set_virtual_address_map;
	ACPI_EFI_CONVERT_POINTER            convert_pointer;
#else
	ACPI_EFI_UNKNOWN_INTERFACE          set_virtual_address_map;
	ACPI_EFI_UNKNOWN_INTERFACE          convert_pointer;
#endif

#if 0
	ACPI_EFI_GET_VARIABLE               get_variable;
	ACPI_EFI_GET_NEXT_VARIABLE_NAME     get_next_variable_name;
	ACPI_EFI_SET_VARIABLE               set_variable;
#else
	ACPI_EFI_UNKNOWN_INTERFACE          get_variable;
	ACPI_EFI_UNKNOWN_INTERFACE          get_next_variable_name;
	ACPI_EFI_UNKNOWN_INTERFACE          set_variable;
#endif

#if 0
	ACPI_EFI_GET_NEXT_HIGH_MONO_COUNT   get_next_high_monotonic_count;
	ACPI_EFI_RESET_SYSTEM               reset_system;
#else
	ACPI_EFI_UNKNOWN_INTERFACE          get_next_high_monotonic_count;
	ACPI_EFI_UNKNOWN_INTERFACE          reset_system;
#endif
};


/*
 * EFI System Table
 */

/*
 * EFI Configuration Table and GUID definitions
 */
#define ACPI_TABLE_GUID \
	{ 0xeb9d2d30, 0x2d88, 0x11d3, {0x9a, 0x16, 0x0, 0x90, 0x27, 0x3f, 0xc1, 0x4d} }
#define ACPI_20_TABLE_GUID \
	{ 0x8868e871, 0xe4f1, 0x11d3, {0xbc, 0x22, 0x0, 0x80, 0xc7, 0x3c, 0x88, 0x81} }

struct _ACPI_EFI_CONFIGURATION_TABLE {
	ACPI_EFI_GUID           vendor_guid;
	VOID                    *vendor_table;
};


#define ACPI_EFI_SYSTEM_TABLE_SIGNATURE 0x5453595320494249
#define ACPI_EFI_SYSTEM_TABLE_REVISION  (ACPI_EFI_SPECIFICATION_MAJOR_REVISION<<16) | (ACPI_EFI_SPECIFICATION_MINOR_REVISION)

struct _ACPI_EFI_SYSTEM_TABLE {
	ACPI_EFI_TABLE_HEADER               hdr;

	CHAR16                              *firmware_vendor;
	u32                                         firmware_revision;

	ACPI_EFI_HANDLE                     console_in_handle;
	ACPI_SIMPLE_INPUT_INTERFACE         *con_in;

	ACPI_EFI_HANDLE                     console_out_handle;
	ACPI_SIMPLE_TEXT_OUTPUT_INTERFACE   *con_out;

	ACPI_EFI_HANDLE                     standard_error_handle;
	ACPI_SIMPLE_TEXT_OUTPUT_INTERFACE   *std_err;

	ACPI_EFI_RUNTIME_SERVICES           *runtime_services;
	ACPI_EFI_BOOT_SERVICES              *boot_services;

	UINTN                               number_of_table_entries;
	ACPI_EFI_CONFIGURATION_TABLE        *configuration_table;
};


/*
 * EFI PCI I/O Protocol
 */
#define ACPI_EFI_PCI_IO_PROTOCOL \
	{ 0x4cf5b200, 0x68b8, 0x4ca5, {0x9e, 0xec, 0xb2, 0x3e, 0x3f, 0x50, 0x2, 0x9a} }

typedef enum {
	acpi_efi_pci_io_width_uint8 = 0,
	acpi_efi_pci_io_width_uint16,
	acpi_efi_pci_io_width_uint32,
	acpi_efi_pci_io_width_uint64,
	acpi_efi_pci_io_width_fifo_uint8,
	acpi_efi_pci_io_width_fifo_uint16,
	acpi_efi_pci_io_width_fifo_uint32,
	acpi_efi_pci_io_width_fifo_uint64,
	acpi_efi_pci_io_width_fill_uint8,
	acpi_efi_pci_io_width_fill_uint16,
	acpi_efi_pci_io_width_fill_uint32,
	acpi_efi_pci_io_width_fill_uint64,
	acpi_efi_pci_io_width_maximum
} ACPI_EFI_PCI_IO_PROTOCOL_WIDTH;

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_PCI_IO_PROTOCOL_CONFIG)(
	struct _ACPI_EFI_PCI_IO             *this,
	ACPI_EFI_PCI_IO_PROTOCOL_WIDTH      width,
	u32                                         offset,
	UINTN                               count,
	VOID                                *buffer);

typedef struct {
	ACPI_EFI_PCI_IO_PROTOCOL_CONFIG     read;
	ACPI_EFI_PCI_IO_PROTOCOL_CONFIG     write;
} ACPI_EFI_PCI_IO_PROTOCOL_CONFIG_ACCESS;

typedef
ACPI_EFI_STATUS
(ACPI_EFI_API *ACPI_EFI_PCI_IO_PROTOCOL_GET_LOCATION)(
	struct _ACPI_EFI_PCI_IO             *this,
	UINTN                               *segment_number,
	UINTN                               *bus_number,
	UINTN                               *device_number,
	UINTN                               *function_number);

struct _ACPI_EFI_PCI_IO {
	ACPI_EFI_UNKNOWN_INTERFACE          poll_mem;
	ACPI_EFI_UNKNOWN_INTERFACE          poll_io;
	ACPI_EFI_UNKNOWN_INTERFACE          mem;
	ACPI_EFI_UNKNOWN_INTERFACE          io;
	ACPI_EFI_PCI_IO_PROTOCOL_CONFIG_ACCESS pci;
	ACPI_EFI_UNKNOWN_INTERFACE          copy_mem;
	ACPI_EFI_UNKNOWN_INTERFACE          map;
	ACPI_EFI_UNKNOWN_INTERFACE          unmap;
	ACPI_EFI_UNKNOWN_INTERFACE          allocate_buffer;
	ACPI_EFI_UNKNOWN_INTERFACE          free_buffer;
	ACPI_EFI_UNKNOWN_INTERFACE          flush;
	ACPI_EFI_PCI_IO_PROTOCOL_GET_LOCATION get_location;
	ACPI_EFI_UNKNOWN_INTERFACE          attributes;
	ACPI_EFI_UNKNOWN_INTERFACE          get_bar_attributes;
	ACPI_EFI_UNKNOWN_INTERFACE          set_bar_attributes;
	u64                                         rom_size;
	VOID                                *rom_image;
};

/* FILE abstraction */

union acpi_efi_file {
	struct _ACPI_EFI_FILE_HANDLE file;
	struct _ACPI_SIMPLE_TEXT_OUTPUT_INTERFACE con_out;
	struct _ACPI_SIMPLE_INPUT_INTERFACE con_in;
};


/* EFI definitions */

#if defined(_GNU_EFI) || defined(_EDK2_EFI)

/*
 * This is needed to hide platform specific code from ACPICA
 */
u64 ACPI_EFI_API
div_u64x32 (
	u64                             dividend,
	UINTN                   divisor,
	UINTN                   *remainder);

u64 ACPI_EFI_API
mult_u64x32 (
	u64                             multiplicand,
	UINTN                   multiplier);

u64 ACPI_EFI_API
lshift_u64 (
	u64                             operand,
	UINTN                   count);

u64 ACPI_EFI_API
rshift_u64 (
	u64                             operand,
	UINTN                   count);

/*
 * EFI specific prototypes
 */
ACPI_EFI_STATUS
efi_main (
	ACPI_EFI_HANDLE         image,
	ACPI_EFI_SYSTEM_TABLE   *system_tab);

int
acpi_main (
	int                             argc,
	char                            *argv[]);

#endif

extern ACPI_EFI_GUID acpi_gbl_loaded_image_protocol;
extern ACPI_EFI_GUID acpi_gbl_text_in_protocol;
extern ACPI_EFI_GUID acpi_gbl_text_out_protocol;
extern ACPI_EFI_GUID acpi_gbl_file_system_protocol;
extern ACPI_EFI_GUID acpi_gbl_generic_file_info;

#endif /* __ACEFIEX_H__ */
