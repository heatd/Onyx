// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#ifndef ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_RUNTIME_SERVICES_H_
#define ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_RUNTIME_SERVICES_H_

#include <onyx/compiler.h>

#include <efi/boot-services.h>
#include <efi/types.h>

__BEGIN_CDECLS

#define EFI_RUNTIME_SERVICES_SIGNATURE 0x56524553544e5552
#define EFI_RUNTIME_SERVICES_REVISION  EFI_SPECIFICATION_VERSION

#define EFI_VARIABLE_NON_VOLATILE                          0x00000001
#define EFI_VARIABLE_BOOTSERVICE_ACCESS                    0x00000002
#define EFI_VARIABLE_RUNTIME_ACCESS                        0x00000004
#define EFI_VARIABLE_HARDWARE_ERROR_RECORD                 0x00000008
#define EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS            0x00000010
#define EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS 0x00000020
#define EFI_VARIABLE_APPEND_WRITE                          0x00000040

// TODO: implement the win_certificate structs if we need them
// typedef struct {
//    uint64_t MonotonicCount;
//    win_certificate_uEFI_GUID AuthInfo;
//} EFI_VARIABLE_AUTHENTICATION;
//
// typedef struct {
//    EFI_TIME TimeStamp;
//    win_certificate_uEFI_GUID AuthInfo;
//} EFI_VARIABLE_AUTHENTICATION_2;

#define EFI_HARDWARE_ERROR_VARIABLE                        \
    {                                                      \
        0x414e6bdd, 0xe47b, 0x47cc,                        \
        {                                                  \
            0xb2, 0x44, 0xbb, 0x61, 0x02, 0x0c, 0xf5, 0x16 \
        }                                                  \
    }

typedef struct
{
    uint16_t Year;
    uint8_t Month;
    uint8_t Day;
    uint8_t Hour;
    uint8_t Minute;
    uint8_t Second;
    uint8_t Pad1;
    uint32_t Nanosecond;
    int16_t TimeZone;
    uint8_t Daylight;
    uint8_t Pad2;
} EFI_TIME;

#define EFI_TIME_ADJUST_DAYLIGHT 0x01
#define EFI_TIME_IN_DAYLIGHT     0x02

#define EFI_UNSPECIFIED_TIMEZONE 0x07FF

typedef struct
{
    uint32_t Resolution;
    uint32_t Accuracy;
    bool SetsToZero;
} EFI_TIME_CAPABILITIES;

#define EFI_OPTIONAL_PTR 0x00000001

typedef enum
{
    EfiResetCold,
    EfiResetWarm,
    EfiResetShutdown,
    EfiResetPlatformSpecific
} EFI_RESET_TYPE;

typedef struct
{
    uint64_t Length;
    union {
        EFI_PHYSICAL_ADDR DataBlock;
        EFI_PHYSICAL_ADDR ContinuationPointer;
    } Union;
} EFI_CAPSUOLE_BLOCK_DESCRIPTOR;

typedef struct
{
    EFI_GUID CapsuleGuid;
    uint32_t HeaderSize;
    uint32_t Flags;
    uint32_t CapsuleImageSize;
} EFI_CAPSULE_HEADER;

#define CAPSULE_FLAGS_PERSIST_ACROSS_RESET  0x00010000
#define CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE 0x00020000
#define CAPSULE_FLAGS_INITIATE_RESET        0x00040000

#define EFI_OS_INDICATIONS_BOOT_TO_FW_UI                   0x0000000000000001
#define EFI_OS_INDICATIONS_TIMESTAMP_REVOCATION            0x0000000000000002
#define EFI_OS_INDICATIONS_FILE_CAPSULE_DELIVERY_SUPPORTED 0x0000000000000004
#define EFI_OS_INDICATIONS_FMP_CAPSULE_SUPPORTED           0x0000000000000008
#define EFI_OS_INDICATIONS_CAPSULE_RESULT_VAR_SUPPORTED    0x0000000000000010
#define EFI_OS_INDICATIONS_START_OS_RECOVERY               0x0000000000000020
#define EFI_OS_INDICATIONS_START_PLATFORM_RECOVERY         0x0000000000000040

#define EFI_CAPSULE_REPORT_GUID                            \
    {                                                      \
        0x39b68c46, 0xf7fb, 0x441b,                        \
        {                                                  \
            0xb6, 0xec, 0x16, 0xb0, 0xf6, 0x98, 0x21, 0xf3 \
        }                                                  \
    }

typedef struct
{
    uint32_t VariableTotalSize;
    uint32_t Reserved;
    EFI_GUID CapsuleGuid;
    EFI_TIME CapsuleProcessed;
    EFI_STATUS CapsuleStatus;
} EFI_CAPSULE_RESULT_VARIABLE_HEADER;

typedef struct
{
    EFI_TABLE_HEADER Hdr;

    EFI_STATUS (*GetTime)(EFI_TIME* time, EFI_TIME_CAPABILITIES* capabilities) EFIAPI;

    EFI_STATUS (*SetTime)(EFI_TIME* time) EFIAPI;

    EFI_STATUS (*GetWakeupTime)(bool* enabled, bool* pending, EFI_TIME* time) EFIAPI;

    EFI_STATUS (*SetWakeupTime)(bool enable, EFI_TIME* time) EFIAPI;

    EFI_STATUS(*SetVirtualAddressMap)
    (size_t memory_map_size, size_t desc_size, uint32_t desc_version,
     EFI_MEMORY_DESCRIPTOR* virtual_map) EFIAPI;

    EFI_STATUS (*ConvertPointer)(size_t debug_disposition, void** addr) EFIAPI;

    EFI_STATUS(*GetVariable)
    (char16_t* var_name, EFI_GUID* vendor_guid, uint32_t* attributes, size_t* data_size,
     void* data) EFIAPI;

    EFI_STATUS(*GetNextVariableName)
    (size_t* var_name_size, char16_t* var_name, EFI_GUID* vendor_guid) EFIAPI;

    EFI_STATUS(*SetVariable)
    (char16_t* var_name, EFI_GUID* vendor_guid, uint32_t attributes, size_t data_size,
     const void* data) EFIAPI;

    EFI_STATUS (*GetNextHighMonotonicCount)(uint32_t* high_count) EFIAPI;

    EFI_STATUS(*ResetSystem)
    (EFI_RESET_TYPE reset_type, EFI_STATUS reset_status, size_t data_size, void* reset_data) EFIAPI;

    EFI_STATUS(*UpdateCapsule)
    (EFI_CAPSULE_HEADER** capsule_header_array, size_t capsule_count,
     EFI_PHYSICAL_ADDR scatter_gather_list) EFIAPI;

    EFI_STATUS(*QueryCapsuleCapabilities)
    (EFI_CAPSULE_HEADER** capsule_header_array, size_t capsule_count, uint64_t* max_capsule_size,
     EFI_RESET_TYPE* reset_type) EFIAPI;

    EFI_STATUS(*QueryVariableInfo)
    (uint32_t attributes, uint64_t* max_var_storage_size, uint64_t* remaining_var_storage_size,
     uint64_t* max_var_size) EFIAPI;
} EFI_RUNTIME_SERVICES;

__END_CDECLS

#endif // ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_RUNTIME_SERVICES_H_
