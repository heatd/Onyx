/** @file
  Extent related routines
  Copyright (c) 2021 - 2022 Pedro Falcato All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <onyx/log.h>

#include "ext4.h"

#define IN
#define CONST const
#define OUT
#if 0
/**
   Checks if the checksum of the extent data block is correct.
   @param[in]      ExtHeader     Pointer to the ext4_extent_header.
   @param[in]      File          Pointer to the file.
   @return TRUE if the checksum is correct, FALSE if there is corruption.
**/
bool Ext4CheckExtentChecksum(IN CONST ext4_extent_header *ExtHeader, IN CONST EXT4_FILE *File);

/**
   Calculates the checksum of the extent data block.
   @param[in]      ExtHeader     Pointer to the ext4_extent_header.
   @param[in]      File          Pointer to the file.
   @return The checksum.
**/
UINT32
Ext4CalculateExtentChecksum(IN CONST ext4_extent_header *ExtHeader, IN CONST EXT4_FILE *File);

/**
   Caches a range of extents, by allocating pool memory for each extent and adding it to the tree.
   @param[in]      File        Pointer to the open file.
   @param[in]      Extents     Pointer to an array of extents.
   @param[in]      NumberExtents Length of the array.
**/
VOID Ext4CacheExtents(IN EXT4_FILE *File, IN CONST ext4_extent *Extents, IN UINT16 NumberExtents);

/**
   Gets an extent from the extents cache of the file.
   @param[in]      File          Pointer to the open file.
   @param[in]      Block         Block we want to grab.
   @return Pointer to the extent, or NULL if it was not found.
**/
ext4_extent *Ext4GetExtentFromMap(IN EXT4_FILE *File, IN UINT32 Block);

#endif

/**
   Check if the extent is uninitialized
   @param[in] Extent    Pointer to the EXT4_EXTENT
   @returns True if uninitialized, else false.
**/
#define EXT4_EXTENT_IS_UNINITIALIZED(Extent) ((Extent)->ee_len > EXT4_EXTENT_MAX_INITIALIZED)

/**
   Retrieves the extent's length, dealing with uninitialized extents in the
process.
   @param[in] Extent      Pointer to the EXT4_EXTENT
   @returns Extent's length, in filesystem blocks.
**/
ext4_block_no Ext4GetExtentLength(IN CONST ext4_extent *Extent);

/**
   Retrieves the pointer to the top of the extent tree.
   @param[in]      Inode         Pointer to the inode structure.
   @return Pointer to an ext4_extent_header. This pointer is inside
           the inode and must not be freed.
**/
static ext4_extent_header *Ext4GetInoExtentHeader(IN ext4_inode *Inode)
{
    return (ext4_extent_header *) Inode->i_data;
}

/**
   Checks if an extent header is valid.
   @param[in]      Header         Pointer to the ext4_extent_header structure.
   @return TRUE if valid, FALSE if not.
**/
static bool Ext4ExtentHeaderValid(IN CONST ext4_extent_header *Header)
{
    if (Header->eh_depth > EXT4_EXTENT_TREE_MAX_DEPTH)
    {
        ERROR("ext4", "Invalid extent header depth %u\n", Header->eh_depth);
        return false;
    }

    if (Header->eh_magic != EXT4_EXTENT_HEADER_MAGIC)
    {
        ERROR("ext4", "Invalid extent header magic %04hx\n", Header->eh_magic);
        return false;
    }

    if (Header->eh_max < Header->eh_entries)
    {
        ERROR("ext4", "Invalid extent header num entries %u max entries %u\n", Header->eh_entries,
              Header->eh_max);
        return false;
    }

    return true;
}

/**
   Performs a binary search for a ext4_extent_index that corresponds to a
   logical block in a given extent tree node.
   @param[in]      Header         Pointer to the ext4_extent_header structure.
   @param[in]      LogicalBlock   Block that will be searched
   @return Pointer to the found ext4_extent_index.
**/
static ext4_extent_index *Ext4BinsearchExtentIndex(IN ext4_extent_header *Header,
                                                   IN ext4_block_no LogicalBlock)
{
    ext4_extent_index *l;
    ext4_extent_index *r;
    ext4_extent_index *m;

    l = ((ext4_extent_index *) (Header + 1)) + 1;
    r = ((ext4_extent_index *) (Header + 1)) + Header->eh_entries - 1;

    // Perform a mostly-standard binary search on the array
    // This works very nicely because the extents arrays are always sorted.

    while (l <= r)
    {
        m = l + (r - l) / 2;

        if (LogicalBlock < m->ei_block)
        {
            r = m - 1;
        }
        else
        {
            l = m + 1;
        }
    }

    return l - 1;
}

/**
   Performs a binary search for a ext4_extent that corresponds to a
   logical block in a given extent tree node.
   @param[in]      Header         Pointer to the ext4_extent_header structure.
   @param[in]      LogicalBlock   Block that will be searched
   @return Pointer to the found ext4_extent_index, else NULL if the array is empty.
           Note: The caller must check if the logical block
           is actually mapped under the given extent.
**/
static ext4_extent *Ext4BinsearchExtentExt(IN ext4_extent_header *Header,
                                           IN ext4_block_no LogicalBlock)
{
    ext4_extent *l;
    ext4_extent *r;
    ext4_extent *m;

    l = ((ext4_extent *) (Header + 1)) + 1;
    r = ((ext4_extent *) (Header + 1)) + Header->eh_entries - 1;
    // Perform a mostly-standard binary search on the array
    // This works very nicely because the extents arrays are always sorted.

    // Empty array
    if (Header->eh_entries == 0)
    {
        return nullptr;
    }

    while (l <= r)
    {
        m = l + (r - l) / 2;

        if (LogicalBlock < m->ee_block)
        {
            r = m - 1;
        }
        else
        {
            l = m + 1;
        }
    }

    return l - 1;
}

/**
   Retrieves the leaf block from an ext4_extent_index.
   @param[in]      Index          Pointer to the ext4_extent_index structure.
   @return Block number of the leaf node.
**/
static ext4_block_no Ext4ExtentIdxLeafBlock(IN ext4_extent_index *Index)
{
    return (((uint64_t) Index->ei_leaf_hi) << 32) | Index->ei_leaf_lo;
}

/**
   Retrieves an extent from an EXT4 inode.
   @param[in]      Partition     Pointer to the opened EXT4 partition.
   @param[in]      File          Pointer to the opened file.
   @param[in]      LogicalBlock  Block number which the returned extent must cover.
   @param[out]     Extent        Pointer to the output buffer, where the extent will be copied to.
   @retval 0 on success, negative error number
**/
int Ext4GetExtent(IN ext4_superblock *Partition, IN ext4_inode *Inode,
                  IN ext4_block_no LogicalBlock, OUT ext4_extent *Extent)
{
    ext4_extent *Ext = nullptr;
    uint32_t CurrentDepth;
    ext4_extent_header *ExtHeader;
    ext4_extent_index *Index;

    // DEBUG((DEBUG_FS, "[ext4] Looking up extent for block %lu\n", LogicalBlock));

    // ext4 does not have support for logical block numbers bigger than UINT32_MAX
    if (LogicalBlock > UINT32_MAX)
    {
        return -EINVAL;
    }

    // Slow path, we'll need to read from disk and (try to) cache those extents.

    ExtHeader = Ext4GetInoExtentHeader(Inode);

    if (!Ext4ExtentHeaderValid(ExtHeader))
    {
        Partition->error("Bad extent header");
        return -EIO;
    }

    CurrentDepth = ExtHeader->eh_depth;
    auto_block_buf bb;

    while (ExtHeader->eh_depth != 0)
    {
        CurrentDepth--;
        // While depth != 0, we're traversing the tree itself and not any leaves
        // As such, every entry is an ext4_extent_index entry
        // Note: Entries after the extent header, either index or actual extent, are always sorted.
        // Therefore, we can use binary search, and it's actually the standard for doing so
        // (see FreeBSD).

        Index = Ext4BinsearchExtentIndex(ExtHeader, LogicalBlock);

        const auto block = Ext4ExtentIdxLeafBlock(Index);

        // Read the leaf block onto the previously-allocated buffer.

        bb = sb_read_block(Partition, block);
        if (!bb)
        {
            Partition->error("Failed to read leaf extent tree block");
            return -EIO;
        }

        ExtHeader = (ext4_extent_header *) block_buf_data(bb);

        if (!Ext4ExtentHeaderValid(ExtHeader))
        {
            Partition->error("Invalid extent header");
            return -EIO;
        }

#if 0
        if (!Ext4CheckExtentChecksum(ExtHeader, File))
        {
            DEBUG((DEBUG_ERROR, "[ext4] Invalid extent checksum\n"));
            FreePool(Buffer);
            return EFI_VOLUME_CORRUPTED;
        }
#endif
        if (ExtHeader->eh_depth != CurrentDepth)
        {
            Partition->error("Invalid extent header depth");
            return -EIO;
        }
    }

    /* We try to cache every extent under a single leaf, since it's quite likely that we
     * may need to access things sequentially. Furthermore, ext4 block allocation as done
     * by linux (and possibly other systems) is quite fancy and usually it results in a small number
     *of extents. Therefore, we shouldn't have any memory issues.
     **/
    // Ext4CacheExtents(File, (ext4_extent *) (ExtHeader + 1), ExtHeader->eh_entries);

    Ext = Ext4BinsearchExtentExt(ExtHeader, LogicalBlock);

    if (!Ext)
    {
        return -ENOENT;
    }

    if (!((LogicalBlock >= Ext->ee_block) &&
          (Ext->ee_block + Ext4GetExtentLength(Ext) > LogicalBlock)))
    {
        return -ENOENT;
    }

    *Extent = *Ext;
    return 0;
}

#if 0

/**
  Compare two ext4_extent structs.
  Used in the extent map's ORDERED_COLLECTION.
  @param[in] UserStruct1  Pointer to the first user structure.
  @param[in] UserStruct2  Pointer to the second user structure.
  @retval <0  If UserStruct1 compares less than UserStruct2.
  @retval  0  If UserStruct1 compares equal to UserStruct2.
  @retval >0  If UserStruct1 compares greater than UserStruct2.
**/
STATIC
INTN EFIAPI Ext4ExtentsMapStructCompare(IN CONST VOID *UserStruct1, IN CONST VOID *UserStruct2)
{
    CONST ext4_extent *Extent1;
    CONST ext4_extent *Extent2;

    Extent1 = UserStruct1;
    Extent2 = UserStruct2;

    return Extent1->ee_block < Extent2->ee_block   ? -1
           : Extent1->ee_block > Extent2->ee_block ? 1
                                                   : 0;
}

/**
  Compare a standalone key against a ext4_extent containing an embedded key.
  Used in the extent map's ORDERED_COLLECTION.
  @param[in] StandaloneKey  Pointer to the bare key.
  @param[in] UserStruct     Pointer to the user structure with the embedded
                            key.
  @retval <0  If StandaloneKey compares less than UserStruct's key.
  @retval  0  If StandaloneKey compares equal to UserStruct's key.
  @retval >0  If StandaloneKey compares greater than UserStruct's key.
**/
STATIC
INTN EFIAPI Ext4ExtentsMapKeyCompare(IN CONST VOID *StandaloneKey, IN CONST VOID *UserStruct)
{
    CONST ext4_extent *Extent;
    UINT32 Block;

    // Note that logical blocks are 32-bits in size so no truncation can happen here
    // with regards to 32-bit architectures.
    Extent = UserStruct;
    Block = (UINT32) (UINTN) StandaloneKey;

    if ((Block >= Extent->ee_block) && (Block - Extent->ee_block < Ext4GetExtentLength(Extent)))
    {
        return 0;
    }

    return Block < Extent->ee_block ? -1 : Block > Extent->ee_block ? 1 : 0;
}

/**
   Initialises the (empty) extents map, that will work as a cache of extents.
   @param[in]      File        Pointer to the open file.
   @return Result of the operation.
**/
EFI_STATUS
Ext4InitExtentsMap(IN EXT4_FILE *File)
{
    File->ExtentsMap = OrderedCollectionInit(Ext4ExtentsMapStructCompare, Ext4ExtentsMapKeyCompare);
    if (!File->ExtentsMap)
    {
        return EFI_OUT_OF_RESOURCES;
    }

    return EFI_SUCCESS;
}

/**
   Frees the extents map, deleting every extent stored.
   @param[in]      File        Pointer to the open file.
**/
VOID Ext4FreeExtentsMap(IN EXT4_FILE *File)
{
    // Keep calling Min(), so we get an arbitrary node we can delete.
    // If Min() returns NULL, it's empty.

    ORDERED_COLLECTION_ENTRY *MinEntry;
    ext4_extent *Ext;

    MinEntry = NULL;

    while ((MinEntry = OrderedCollectionMin(File->ExtentsMap)) != NULL)
    {
        OrderedCollectionDelete(File->ExtentsMap, MinEntry, (VOID **) &Ext);
        FreePool(Ext);
    }

    ASSERT(OrderedCollectionIsEmpty(File->ExtentsMap));

    OrderedCollectionUninit(File->ExtentsMap);
    File->ExtentsMap = NULL;
}

/**
   Caches a range of extents, by allocating pool memory for each extent and adding it to the tree.
   @param[in]      File        Pointer to the open file.
   @param[in]      Extents     Pointer to an array of extents.
   @param[in]      NumberExtents Length of the array.
**/
VOID Ext4CacheExtents(IN EXT4_FILE *File, IN CONST ext4_extent *Extents, IN UINT16 NumberExtents)
{
    UINT16 Idx;
    ext4_extent *Extent;
    EFI_STATUS Status;

    /* Note that any out of memory condition might mean we don't get to cache a whole leaf of
     * extents in which case, future insertions might fail.
     */

    for (Idx = 0; Idx < NumberExtents; Idx++, Extents++)
    {
        Extent = AllocatePool(sizeof(ext4_extent));

        if (Extent == NULL)
        {
            return;
        }

        CopyMem(Extent, Extents, sizeof(ext4_extent));
        Status = OrderedCollectionInsert(File->ExtentsMap, NULL, Extent);

        // EFI_ALREADY_STARTED = already exists in the tree.
        if (EFI_ERROR(Status))
        {
            FreePool(Extent);

            if (Status == EFI_ALREADY_STARTED)
            {
                continue;
            }

            return;
        }
    }
}

/**
   Gets an extent from the extents cache of the file.
   @param[in]      File          Pointer to the open file.
   @param[in]      Block         Block we want to grab.
   @return Pointer to the extent, or NULL if it was not found.
**/
ext4_extent *Ext4GetExtentFromMap(IN EXT4_FILE *File, IN UINT32 Block)
{
    ORDERED_COLLECTION_ENTRY *Entry;

    Entry = OrderedCollectionFind(File->ExtentsMap, (CONST VOID *) (UINTN) Block);

    if (Entry == NULL)
    {
        return NULL;
    }

    return OrderedCollectionUserStruct(Entry);
}

/**
   Calculates the checksum of the extent data block.
   @param[in]      ExtHeader     Pointer to the ext4_extent_header.
   @param[in]      File          Pointer to the file.
   @return The checksum.
**/
UINT32
Ext4CalculateExtentChecksum(IN CONST ext4_extent_header *ExtHeader, IN CONST EXT4_FILE *File)
{
    UINT32 Csum;
    EXT4_PARTITION *Partition;
    EXT4_INODE *Inode;

    Partition = File->Partition;
    Inode = File->Inode;

    Csum = Ext4CalculateChecksum(Partition, &File->InodeNum, sizeof(EXT4_INO_NR),
                                 Partition->InitialSeed);
    Csum =
        Ext4CalculateChecksum(Partition, &Inode->i_generation, sizeof(Inode->i_generation), Csum);
    Csum = Ext4CalculateChecksum(Partition, ExtHeader,
                                 Partition->BlockSize - sizeof(ext4_extent_TAIL), Csum);

    return Csum;
}

#endif

#if 0
/**
   Checks if the checksum of the extent data block is correct.
   @param[in]      ExtHeader     Pointer to the ext4_extent_header.
   @param[in]      File          Pointer to the file.
   @return TRUE if the checksum is correct, FALSE if there is corruption.
**/
bool Ext4CheckExtentChecksum(IN CONST ext4_extent_header *ExtHeader, IN CONST EXT4_FILE *File)
{
    EXT4_PARTITION *Partition;
    ext4_extent_TAIL *Tail;

    Partition = File->Partition;

    if (!EXT4_HAS_METADATA_CSUM(Partition))
    {
        return TRUE;
    }

    Tail = (ext4_extent_TAIL *) ((CONST CHAR8 *) ExtHeader + (Partition->BlockSize - 4));

    return Tail->eb_checksum == Ext4CalculateExtentChecksum(ExtHeader, File);
}
#endif

/**
   Retrieves the extent's length, dealing with uninitialized extents in the process.
   @param[in] Extent      Pointer to the ext4_extent
   @returns Extent's length, in filesystem blocks.
**/
ext4_block_no Ext4GetExtentLength(IN CONST ext4_extent *Extent)
{
    // If it's an unintialized extent, the true length is ee_len - 2^15
    if (EXT4_EXTENT_IS_UNINITIALIZED(Extent))
    {
        return Extent->ee_len - EXT4_EXTENT_MAX_INITIALIZED;
    }

    return Extent->ee_len;
}

/**
 * @brief Get the underlying block from a logical block, for a given inode
 *
 * @param sb Superblock
 * @param ino Inode
 * @param block Logical block
 * @return ext4 block, or a negative error number
 */
expected<ext4_block_no, int> ext4_emap_get_block(ext4_superblock *sb, ext4_inode *ino,
                                                 ext4_block_no block)
{
    ext4_extent e;
    if (int st = Ext4GetExtent(sb, ino, block, &e); st < 0)
    {
        if (st == -ENOENT)
            return EXT4_FILE_HOLE_BLOCK;
        return unexpected<int>{st};
    }

    if (EXT4_EXTENT_IS_UNINITIALIZED(&e))
        return EXT4_FILE_HOLE_BLOCK;
    return (e.ee_start_lo | (uint64_t) e.ee_start_hi << 32) + (block - e.ee_block);
}
