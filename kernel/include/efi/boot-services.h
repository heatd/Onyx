// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#ifndef ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_BOOT_SERVICES_H_
#define ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_BOOT_SERVICES_H_

#include <stdbool.h>

#include <onyx/compiler.h>

#include <efi/protocol/device-path.h>
#include <efi/types.h>

#define EFI_BOOT_SERVICES_SIGNATURE 0x56524553544f4f42
#define EFI_BOOT_SERVICES_REVISION  EFI_SPECIFICATION_VERSION

__BEGIN_CDECLS

typedef size_t EFI_TPL;

#define TPL_APPLICATION 4
#define TPL_CALLBACK    8
#define TPL_NOTIFY      16
#define TPL_HIGH_LEVEL  31

typedef enum
{
    AllocateAnyPages,
    AllocateMaxAddress,
    AllocateAddress,
    MaxAllocateType
} EFI_ALLOCATE_TYPE;

typedef struct
{
    uint32_t Type;
    uint32_t Padding;
    EFI_PHYSICAL_ADDR PhysicalStart;
    EFI_VIRTUAL_ADDR VirtualStart;
    uint64_t NumberOfPages;
    uint64_t Attribute;
} EFI_MEMORY_DESCRIPTOR;

#define EFI_MEMORY_UC            0x0000000000000001
#define EFI_MEMORY_WC            0x0000000000000002
#define EFI_MEMORY_WT            0x0000000000000004
#define EFI_MEMORY_WB            0x0000000000000008
#define EFI_MEMORY_UCE           0x0000000000000010
#define EFI_MEMORY_WP            0x0000000000001000
#define EFI_MEMORY_RP            0x0000000000002000
#define EFI_MEMORY_XP            0x0000000000004000
#define EFI_MEMORY_NV            0x0000000000008000
#define EFI_MEMORY_MORE_RELIABLE 0x0000000000010000
#define EFI_MEMORY_RO            0x0000000000020000
#define EFI_MEMORY_RUNTIME       0x8000000000000000

#define EFI_MEMORY_DESCRIPTOR_VERSION 1

typedef enum
{
    EFI_NATIVE_INTERFACE
} EFI_INTERFACE_TYPE;

typedef enum
{
    AllHandles,
    ByRegisterNotify,
    ByProtocol
} EFI_LOCATE_SEARCH_TYPE;

#define EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL  0x00000001
#define EFI_OPEN_PROTOCOL_GET_PROTOCOL        0x00000002
#define EFI_OPEN_PROTOCOL_TEST_PROTOCOL       0x00000004
#define EFI_OPEN_PROTOCOL_BY_CHILD_CONTROLLER 0x00000008
#define EFI_OPEN_PROTOCOL_BY_DRIVER           0x00000010
#define EFI_OPEN_PROTOCOL_EXCLUSIVE           0x00000020

typedef struct
{
    EFI_HANDLE agent_handle;
    EFI_HANDLE controller_handle;
    uint32_t attributes;
    uint32_t open_count;
} EFI_OPEN_PROTOCOL_INFORMATION_ENTRY;

#define EFI_HII_PACKAGE_LIST_PROTOCOL_GUID                 \
    {                                                      \
        0x6a1ee763, 0xd47a, 0x43b4,                        \
        {                                                  \
            0xaa, 0xbe, 0xef, 0x1d, 0xe2, 0xab, 0x56, 0xfc \
        }                                                  \
    }

typedef struct EFI_HII_PACKAGE_LIST_HEADER EFI_HII_PACKAGE_LIST_HEADER;
typedef EFI_HII_PACKAGE_LIST_HEADER* EFI_HII_PACKAGE_LIST_PROTOCOL;

// fwd declare EFI_SYSTEM_TABLE to break circular dependencies
typedef struct EFI_SYSTEM_TABLE EFI_SYSTEM_TABLE;
typedef EFI_STATUS (*EFI_IMAGE_ENTRY_POINT)(EFI_HANDLE img, EFI_SYSTEM_TABLE* sys) EFIAPI;

typedef struct
{
    EFI_TABLE_HEADER Hdr;

    EFI_TPL (*RaiseTPL)(EFI_TPL new_tpl) EFIAPI;

    void (*RestoreTPL)(EFI_TPL old_tpl) EFIAPI;

    EFI_STATUS(*AllocatePages)
    (EFI_ALLOCATE_TYPE type, EFI_MEMORY_TYPE memory_type, size_t pages,
     EFI_PHYSICAL_ADDR* memory) EFIAPI;

    EFI_STATUS (*FreePages)(EFI_PHYSICAL_ADDR memory, size_t pages) EFIAPI;

    EFI_STATUS(*GetMemoryMap)
    (size_t* memory_map_size, EFI_MEMORY_DESCRIPTOR* memory_map, size_t* map_key, size_t* desc_size,
     uint32_t* desc_version) EFIAPI;

    EFI_STATUS (*AllocatePool)(EFI_MEMORY_TYPE pool_type, size_t size, void** buf) EFIAPI;

    EFI_STATUS (*FreePool)(void* buf) EFIAPI;

    EFI_STATUS(*CreateEvent)
    (uint32_t type, EFI_TPL notify_tpl, EFI_EVENT_NOTIFY notify_fn, void* notify_ctx,
     EFI_EVENT* event) EFIAPI;

    EFI_STATUS (*SetTimer)(EFI_EVENT event, EFI_TIMEr_delay type, uint64_t trigger_time) EFIAPI;

    EFI_STATUS (*WaitForEvent)(size_t num_events, EFI_EVENT* event, size_t* index) EFIAPI;

    EFI_STATUS (*SignalEvent)(EFI_EVENT event) EFIAPI;

    EFI_STATUS (*CloseEvent)(EFI_EVENT event) EFIAPI;

    EFI_STATUS (*CheckEvent)(EFI_EVENT event) EFIAPI;

    EFI_STATUS(*InstallProtocolInterface)
    (EFI_HANDLE* handle, const EFI_GUID* protocol, EFI_INTERFACE_TYPE intf_type, void* intf) EFIAPI;

    EFI_STATUS(*ReinstallProtocolInterface)
    (EFI_HANDLE handle, const EFI_GUID* protocol, void* old_intf, void* new_intf) EFIAPI;

    EFI_STATUS(*UninstallProtocolInterface)
    (EFI_HANDLE handle, const EFI_GUID* protocol, void* intf) EFIAPI;

    EFI_STATUS (*HandleProtocol)(EFI_HANDLE handle, const EFI_GUID* protocol, void** intf) EFIAPI;

    void* Reserved;

    EFI_STATUS(*RegisterProtocolNotify)
    (const EFI_GUID* protocol, EFI_EVENT event, void** registration) EFIAPI;

    EFI_STATUS(*LocateHandle)
    (EFI_LOCATE_SEARCH_TYPE search_type, const EFI_GUID* protocol, void* search_key,
     size_t* buf_size, EFI_HANDLE* buf) EFIAPI;

    EFI_STATUS(*LocateDevicePath)
    (const EFI_GUID* protocol, EFI_DEVICE_PATH_PROTOCOL** path, EFI_HANDLE* device) EFIAPI;

    EFI_STATUS (*InstallConfigurationTable)(const EFI_GUID* guid, void* table) EFIAPI;

    EFI_STATUS(*LoadImage)
    (bool boot_policy, EFI_HANDLE parent_image_handle, EFI_DEVICE_PATH_PROTOCOL* path, void* src,
     size_t src_size, EFI_HANDLE* image_handle) EFIAPI;

    EFI_STATUS(*StartImage)
    (EFI_HANDLE image_handle, size_t* exit_data_size, char16_t** exit_data) EFIAPI;

    EFI_STATUS(*Exit)
    (EFI_HANDLE image_handle, EFI_STATUS exit_status, size_t exit_data_size,
     char16_t* exit_data) EFIAPI;

    EFI_STATUS (*UnloadImage)(EFI_HANDLE image_handle) EFIAPI;

    EFI_STATUS (*ExitBootServices)(EFI_HANDLE image_handle, size_t map_key) EFIAPI;

    EFI_STATUS (*GetNextMonotonicCount)(uint64_t* count) EFIAPI;

    EFI_STATUS (*Stall)(size_t microseconds) EFIAPI;

    EFI_STATUS(*SetWatchdogTimer)
    (size_t timeout, uint64_t watchdog_code, size_t data_size, char16_t* watchdog_data) EFIAPI;

    EFI_STATUS(*ConnectController)
    (EFI_HANDLE controller_handle, EFI_HANDLE* driver_image_handle,
     EFI_DEVICE_PATH_PROTOCOL* remaining_path, bool recursive) EFIAPI;

    EFI_STATUS(*DisconnectController)
    (EFI_HANDLE controller_handle, EFI_HANDLE driver_image_handle, EFI_HANDLE child_handle) EFIAPI;

    EFI_STATUS(*OpenProtocol)
    (EFI_HANDLE handle, const EFI_GUID* protocol, void** intf, EFI_HANDLE agent_handle,
     EFI_HANDLE controller_handle, uint32_t attributes) EFIAPI;

    EFI_STATUS(*CloseProtocol)
    (EFI_HANDLE handle, const EFI_GUID* protocol, EFI_HANDLE agent_handle,
     EFI_HANDLE controller_handle) EFIAPI;

    EFI_STATUS(*OpenProtocolInformation)
    (EFI_HANDLE handle, const EFI_GUID* protocol, EFI_OPEN_PROTOCOL_INFORMATION_ENTRY** entry_buf,
     size_t* entry_count) EFIAPI;

    EFI_STATUS(*ProtocolsPerHandle)
    (EFI_HANDLE handle, EFI_GUID*** protocol_buf, size_t* protocol_buf_count) EFIAPI;

    EFI_STATUS(*LocateHandleBuffer)
    (EFI_LOCATE_SEARCH_TYPE search_type, const EFI_GUID* protocol, void* search_key,
     size_t* num_handles, EFI_HANDLE** buf) EFIAPI;

    EFI_STATUS (*LocateProtocol)(const EFI_GUID* protocol, void* registration, void** intf) EFIAPI;

    EFI_STATUS (*InstallMultipleProtocolInterfaces)(EFI_HANDLE* handle, ...) EFIAPI;

    EFI_STATUS (*UninstallMultipleProtocolInterfaces)(EFI_HANDLE handle, ...) EFIAPI;

    EFI_STATUS (*CalculateCrc32)(void* data, size_t len, uint32_t* crc32) EFIAPI;

    void (*CopyMem)(void* dest, const void* src, size_t len) EFIAPI;

    void (*SetMem)(void* buf, size_t len, uint8_t val) EFIAPI;

    EFI_STATUS(*CreateEventEx)
    (uint32_t type, EFI_TPL notify_tpl, EFI_EVENT_NOTIFY notify_fn, const void* notify_ctx,
     const EFI_GUID* event_group, EFI_EVENT* event) EFIAPI;
} EFI_BOOT_SERVICES;

__END_CDECLS

#endif // ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_BOOT_SERVICES_H_
