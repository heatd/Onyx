// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#ifndef ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_GRAPHICS_OUTPUT_H_
#define ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_GRAPHICS_OUTPUT_H_

#include <onyx/compiler.h>

#include <efi/types.h>

__BEGIN_CDECLS

#define EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID                  \
    {                                                      \
        0x9042a9de, 0x23dc, 0x4a38,                        \
        {                                                  \
            0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a \
        }                                                  \
    }
extern const EFI_GUID GraphicsOutputProtocol;

typedef struct
{
    uint32_t RedMask;
    uint32_t GreenMask;
    uint32_t BlueMask;
    uint32_t ReservedMask;
} EFI_PIXEL_BITMASK;

typedef enum
{
    PixelRedGreenBlueReserved8BitPerColor,
    PixelBlueGreenRedReserved8BitPerColor,
    PixelBitMask,
    PixelBltOnly,
    PixelFormatMax
} EFI_GRAPHICS_PIXEL_FORMAT;

typedef struct
{
    uint32_t Version;
    uint32_t HorizontalResolution;
    uint32_t VerticalResolution;
    EFI_GRAPHICS_PIXEL_FORMAT PixelFormat;
    EFI_PIXEL_BITMASK PixelInformation;
    uint32_t PixelsPerScanLine;
} EFI_GRAPHICS_OUTPUT_MODE_INFORMATION;

typedef struct
{
    uint32_t MaxMode;
    uint32_t Mode;
    EFI_GRAPHICS_OUTPUT_MODE_INFORMATION* Info;
    size_t SizeOfInfo;
    EFI_PHYSICAL_ADDR FrameBufferBase;
    size_t FrameBufferSize;
} EFI_GRAPHICS_OUTPUT_MODE;

typedef struct
{
    uint8_t Blue;
    uint8_t Green;
    uint8_t Red;
    uint8_t Reserved;
} EFI_GRAPHICS_OUTPUT_BLT_PIXEL;

typedef enum
{
    EfiBltVideoFill,
    EfiBltVideoToBltBuffer,
    EfiBltBufferToVideo,
    EfiBltVideoToVideo,
    EfiGraphicsOutputBltOperationMax
} EFI_GRAPHICS_OUTPUT_BLT_OPERATION;

typedef struct EFI_GRAPHICS_OUTPUT_PROTOCOL
{
    EFI_STATUS(*QueryMode)
    (struct EFI_GRAPHICS_OUTPUT_PROTOCOL* self, uint32_t mode_num, size_t* info_len,
     EFI_GRAPHICS_OUTPUT_MODE_INFORMATION** info) EFIAPI;

    EFI_STATUS (*SetMode)(struct EFI_GRAPHICS_OUTPUT_PROTOCOL* self, uint32_t mode_num) EFIAPI;

    EFI_STATUS(*Blt)
    (struct EFI_GRAPHICS_OUTPUT_PROTOCOL* self, EFI_GRAPHICS_OUTPUT_BLT_PIXEL* blt_buf,
     EFI_GRAPHICS_OUTPUT_BLT_OPERATION blt_operation, size_t src_x, size_t src_y, size_t dest_x,
     size_t dest_y, size_t width, size_t height, size_t delta) EFIAPI;

    EFI_GRAPHICS_OUTPUT_MODE* Mode;
} EFI_GRAPHICS_OUTPUT_PROTOCOL;

__END_CDECLS

#endif // ZIRCON_KERNEL_LIB_EFI_INCLUDE_EFI_PROTOCOL_GRAPHICS_OUTPUT_H_
