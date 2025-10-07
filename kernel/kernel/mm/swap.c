/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#define pr_fmt(fmt) "swap: " fmt
#include <stdio.h>

#include <onyx/bio.h>
#include <onyx/buffer.h>
#include <onyx/cpu.h>
#include <onyx/err.h>
#include <onyx/file.h>
#include <onyx/filemap.h>
#include <onyx/maple_tree.h>
#include <onyx/mm/page_lru.h>
#include <onyx/mm/slab.h>
#include <onyx/namei.h>
#include <onyx/pgtable.h>
#include <onyx/rcupdate.h>
#include <onyx/user.h>
#include <onyx/vfs.h>
#include <onyx/vm_fault.h>

#include <uapi/swap.h>

/* Simple (sample) pcpu counter for approx. swap usage. Should be refactored to a proper lib once
 * e.g pcpu alloc gets straighted out. */
struct pcpu_counter
{
    unsigned long counter;
    u16 batch;
    s16 pcpu[CONFIG_SMP_NR_CPUS];
};

typedef __swap_block_t swap_block_t;

struct swap_extent
{
    u64 logical_block;
    u64 physical_block;
    u64 length;
};

struct swap_block_group
{
    u8 *start, *end;
    unsigned long nr_free;
    int smallest_bit_free;
    struct spinlock lock;
};

struct swap_area
{
    unsigned long refs;
    union {
        struct
        {
            struct file *file;
            int flags;
            int prio;
        };
        struct rcu_head rcu_head;
    };

    /* Points to the file's bdev (if a block device), or the partition itself. */
    struct blockdev *bdev;
    swap_block_t nr_pages;
    swap_block_t swap_off;

    struct maple_tree extents_tree;
    struct swap_block_group *block_groups;
    unsigned long nr_block_groups;

    u8 *swap_map;
    struct vm_object *swap_space;
};

static inline struct blockdev *blkdev_get_dev(struct file *f)
{
    return (struct blockdev *) f->f_ino->i_helper;
}

unsigned int bdev_sector_size(struct blockdev *bdev);

#define SWAP_COUNTER_BATCH 32

static ssize_t swap_writepage(struct vm_object *vm_obj, struct page *page, size_t off);
const struct vm_object_ops swap_ops = {.writepage = swap_writepage};

static struct pcpu_counter swap_usage = {.batch = SWAP_COUNTER_BATCH};
static unsigned long total_swap = 0;

static void __swap_add_counter(s16 npages)
{
    unsigned int cpu = get_cpu_nr();
    int result = swap_usage.pcpu[cpu] + npages;
    if (result <= -swap_usage.batch || result >= swap_usage.batch)
    {
        __atomic_add_fetch(&swap_usage.counter, result, __ATOMIC_RELAXED);
        swap_usage.pcpu[cpu] = 0;
    }
    else
        swap_usage.pcpu[cpu] += npages;
}

static void swap_add_counter(s16 npages)
{
    sched_disable_preempt();
    __swap_add_counter(npages);
    sched_enable_preempt();
}

static void __swap_flush_counter(void)
{
    unsigned int cpu = get_cpu_nr();
    __atomic_add_fetch(&swap_usage.counter, swap_usage.pcpu[cpu], __ATOMIC_RELAXED);
    swap_usage.pcpu[cpu] = 0;
}

static void swap_flush_counter(void)
{
    sched_disable_preempt();
    __swap_flush_counter();
    sched_enable_preempt();
}

/**
 * @brief Check if indeed we have some swap space available
 * This function is not precise and may return false negatives/positives.
 * Used by page reclaim code to avoid anon page reclaim when no swap is available
 *
 * @return True if it _looks_ like swap is available, else false
 */
bool swap_is_available(void)
{
    return READ_ONCE(swap_usage.counter) < total_swap;
}

unsigned long swap_free(void)
{
    return READ_ONCE(swap_usage.counter);
}

unsigned long swap_total(void)
{
    return READ_ONCE(total_swap);
}

#define MAX_SWAP_AREAS 16

struct spinlock swap_areas_lock;
static struct swap_area *swap_areas[MAX_SWAP_AREAS];
struct vm_object *swap_spaces[MAX_SWAP_AREAS];

/**
 * @brief Set the block device's block size
 *
 * @param bdev Block device
 * @param block_size Block size
 * @return 0 on success, negative error codes
 */
int block_set_bsize(struct blockdev *bdev, unsigned int block_size);

static int parse_super(struct swap_area *swp)
{
    /* Swap is read and written to in page units */
    int err = block_set_bsize(swp->bdev, PAGE_SIZE);
    if (err < 0)
        return err;

    struct block_buf *bb = bdev_read_block(swp->bdev, 0);
    if (!bb)
        return -EIO;

    struct swap_super *super = block_buf_data(bb);

    err = -EINVAL;
    if (super->swp_magic != SWAP_MAGIC)
    {
        pr_err("Bad swap magic %llx\n", (unsigned long long) super->swp_magic);
        goto out;
    }

    if (super->swp_flags & SWP_FLAG_BAD)
    {
        pr_err("Bad swap partition\n");
        goto out;
    }

    if (super->swp_pagesize != PAGE_SIZE)
    {
        pr_err("Configured page size (%u) != the system's page size (%lu)\n", super->swp_pagesize,
               PAGE_SIZE);
        goto out;
    }

    if (super->swp_nr_pages <= MIN_SWAP_SIZE_PAGES)
    {
        pr_err("Configured swap area is too small (%llu pages, should be %d)\n",
               (unsigned long long) super->swp_nr_pages, MIN_SWAP_SIZE_PAGES);
        goto out;
    }

    swp->nr_pages = super->swp_nr_pages - MIN_SWAP_SIZE_PAGES;
    swp->swap_off = MIN_SWAP_SIZE_PAGES;
    err = 0;
out:
    block_buf_put(bb);
    return err;
}

/**
 * @brief Destroy a partially constructed swap area
 *
 * @param sa Swap area
 */
static void swap_area_destroy_early(struct swap_area *sa)
{
    /* No need to use RCU for any of this stuff here, we haven't exposed this swap area yet */
    unsigned long index = 0;
    struct swap_extent *se;
    mt_for_each (&sa->extents_tree, se, index, -1UL)
        kfree(se);

    mtree_destroy(&sa->extents_tree);

    if (sa->block_groups)
        vfree(sa->block_groups);
    if (sa->swap_map)
        vfree(sa->swap_map);

    if (sa->file)
        fd_put(sa->file);
    kfree(sa);
}

static int swap_setup_map(struct swap_area *sa)
{
    sa->swap_map =
        vmalloc(vm_size_to_pages(sa->nr_pages), VM_TYPE_REGULAR, VM_READ | VM_WRITE, GFP_KERNEL);
    if (!sa->swap_map)
    {
        pr_err("Failed to allocate a %lukB sized swap_map\n", sa->nr_pages / 1024);
        return -ENOMEM;
    }

    /* TODO: Sizing block groups is... weird. We'll try to size them like a filesystem for now. But
     * it's not ideal concurrency-wise if we have a smaller swap. */
#define MAX_BLOCK_GROUP_SIZE (PAGE_SIZE / 2)
    sa->nr_block_groups = sa->nr_pages / MAX_BLOCK_GROUP_SIZE;
    if (sa->nr_pages % MAX_BLOCK_GROUP_SIZE)
        sa->nr_block_groups++;

    sa->block_groups =
        vmalloc(vm_size_to_pages(sa->nr_block_groups * sizeof(struct swap_block_group)),
                VM_TYPE_REGULAR, VM_WRITE | VM_READ, GFP_KERNEL);
    if (!sa->block_groups)
    {
        pr_err("Failed to allocate an %lukB sized array of swap_block_groups\n",
               sa->nr_block_groups * sizeof(struct swap_block_group) / 1024);
        return -ENOMEM;
    }

    for (unsigned long i = 0, start = 0; i < sa->nr_block_groups;
         i++, start += MAX_BLOCK_GROUP_SIZE)
    {
        struct swap_block_group *bg = &sa->block_groups[i];
        unsigned long size = min(sa->nr_pages - start, MAX_BLOCK_GROUP_SIZE);
        bg->start = sa->swap_map + start;
        bg->end = bg->start + size;
        bg->nr_free = size;
        bg->smallest_bit_free = 0;
        spinlock_init(&bg->lock);
    }

    return 0;
}

static int swap_install(struct swap_area *sa)
{
    int err = 1;
    spin_lock(&swap_areas_lock);

    for (int i = 0; i < MAX_SWAP_AREAS; i++)
    {
        if (!swap_areas[i])
        {
            swap_areas[i] = sa;
            swap_spaces[i] = sa->swap_space;
            __atomic_add_fetch(&total_swap, sa->nr_pages, __ATOMIC_RELAXED);
            err = 0;
            break;
        }
    }

    spin_unlock(&swap_areas_lock);

    if (err)
        pr_err("Failed to install swap area: limit reached\n");
    return err ? -ESRCH : 0;
}

static int do_swapon(struct file *swapfile, int flags)
{
    int err = -ENOMEM, prio;
    unsigned long nr_pages;
    struct swap_area *swp = kmalloc(sizeof(*swp), GFP_KERNEL);
    if (!swp)
    {
        fd_put(swapfile);
        return err;
    }

    memset(swp, 0, sizeof(*swp));
    swp->refs = 1;
    swp->file = swapfile;
    swp->flags = flags;
    swp->bdev = blkdev_get_dev(swapfile);
    swp->extents_tree = (struct maple_tree) MTREE_INIT(swp->extents_tree, MT_FLAGS_USE_RCU);

    /* Set up a simple extent covering the whole thing, for block devices */
    struct swap_extent *extent = kmalloc(sizeof(*extent), GFP_KERNEL);
    if (!extent)
    {
        err = -ENOMEM;
        goto out_err;
    }

    extent->length = -1ULL;
    extent->logical_block = 0;
    extent->physical_block = 0;
    err = mtree_insert_range(&swp->extents_tree, 0, -1UL, extent, GFP_KERNEL);
    if (err < 0)
        goto out_err;

    err = parse_super(swp);
    if (err < 0)
        goto out_err;

    err = swap_setup_map(swp);
    if (err < 0)
        goto out_err;
    swp->swap_space = vmo_create(swp->nr_pages + swp->swap_off, swp);
    if (!swp->swap_space)
        goto out_err;
    swp->swap_space->ops = &swap_ops;

    /* Read it before installing, since we lose the swap_area's ownership */
    prio = swp->prio;
    nr_pages = swp->nr_pages;

    err = swap_install(swp);
    if (err < 0)
        goto out_err;

    pr_info("Installed swap area with %lukB, priority %d\n", nr_pages * PAGE_SIZE / 1024, prio);
    return 0;
out_err:
    swap_area_destroy_early(swp);
    return err;
}

#define VALID_SWAPON_FLAGS 0

int sys_swapon(const char *upath, int flags)
{
    int err = 0;

    if (flags & ~VALID_SWAPON_FLAGS)
        return -EINVAL;

    const char *path = strcpy_from_user(upath);
    if (!path)
        return -ENOMEM;

    /* We use O_EXCL to _possibly_ grab the bdev atomically  */
    struct file *file = c_vfs_open(AT_FDCWD, path, O_RDWR | O_EXCL, 0);
    if (IS_ERR(file))
    {
        err = PTR_ERR(file);
        goto err;
    }

    if (!S_ISBLK(file->f_ino->i_mode))
    {
        pr_err("Attempted to use %s as a swap area, which is not yet supported. Only block "
               "devices are supported yet.\n",
               path);
        err = -EINVAL;
        fd_put(file);
        goto err;
    }

    return do_swapon(file, flags);
err:
    free((void *) path);
    return err;
}

int sys_swapoff(const char *upath)
{
    return -ENOSYS;
}

#define SWAP_MAX_USAGE     0x7f
#define SWAP_MAP_SWAPCACHE 0x80

static int swap_alloc_from_block_group(struct swap_area *sa, int area, struct swap_block_group *bg,
                                       unsigned long bgno, struct page *page)
{
    u8 *map;
    int err = -ENOSPC;
    unsigned long offset;
    spin_lock(&bg->lock);
    /* Recheck bg->nr_free under the lock. We've checked it out of the lock using READ_ONCE before,
     * thus it's unlikely we're here unless we were reading stale data.
     */
    if (unlikely(bg->nr_free == 0))
        goto out;

    map = bg->start;
    while (map != bg->end)
    {
        if (!*map)
        {
            WARN_ON(bg->nr_free == 0);
            *map = SWAP_MAP_SWAPCACHE;
            offset = (bgno * MAX_BLOCK_GROUP_SIZE) + map - bg->start + sa->swap_off;
            page->priv = SWP_ENTRY((unsigned long) area, offset).swp;
            WARN_ON(page_test_swap(page));
            page_set_swap(page);
            err = 0;
            bg->nr_free--;
            __swap_add_counter(1);
            break;
        }

        map++;
    }

out:
    spin_unlock(&bg->lock);
    return err;
}

static int swap_alloc_from_area(struct swap_area *swap, int area, struct page *page)
{
    int err = -ENOSPC;
    for (unsigned long i = 0; i < swap->nr_block_groups; i++)
    {
        struct swap_block_group *bg = &swap->block_groups[i];
        if (!READ_ONCE(bg->nr_free))
            continue;
        err = swap_alloc_from_block_group(swap, area, bg, i, page);
        if (!err)
            break;
    }

    return err;
}

static int swap_allocate(struct page *page)
{
    int err = -ENOSPC;
    struct swap_area *sa;
    rcu_read_lock();
    for (unsigned int i = 0; i < MAX_SWAP_AREAS; i++)
    {
        sa = swap_areas[i];
        if (!sa)
            continue;
        err = swap_alloc_from_area(sa, i, page);
        if (!err)
            break;
    }
    rcu_read_unlock();

    return err;
}

bool swap_put(swp_entry_t entry)
{
    struct swap_area *sa = swap_areas[SWP_TYPE(entry)];
    unsigned long eff_off = SWP_OFFSET(entry) - sa->swap_off;
    struct swap_block_group *bg = &sa->block_groups[eff_off / MAX_BLOCK_GROUP_SIZE];
    u8 *map;
    u8 count;

    spin_lock(&bg->lock);

    map = bg->start + (eff_off % MAX_BLOCK_GROUP_SIZE);
    count = *map & ~SWAP_MAP_SWAPCACHE;

#if CONFIG_DEBUG_SWAP
    pr_warn("swap count %hu -> %u\n", count, count ? count - 1 : 0);
#endif
    if (count)
    {
        (*map)--;
        count--;
    }

    spin_unlock(&bg->lock);
    return count == 0;
}

static bool swap_put_page(struct page *page)
{
    swp_entry_t entry = swpval_to_swp_entry(page->priv);
    return swap_put(entry);
}

static void swap_final_put(swp_entry_t swp)
{
    struct swap_area *sa = swap_areas[SWP_TYPE(swp)];
    unsigned long eff_off = SWP_OFFSET(swp) - sa->swap_off;
    struct swap_block_group *bg = &sa->block_groups[eff_off / MAX_BLOCK_GROUP_SIZE];
    u8 *map;
    u8 count;

    spin_lock(&bg->lock);

    map = bg->start + (eff_off % MAX_BLOCK_GROUP_SIZE);
    count = *map & ~SWAP_MAP_SWAPCACHE;
    if (WARN_ON_ONCE(count > 0))
    {
        spin_unlock(&bg->lock);
        return;
    }

    *map = 0;
    spin_unlock(&bg->lock);
}

static u8 swap_get_map(swp_entry_t swp)
{
    struct swap_area *sa = swap_areas[SWP_TYPE(swp)];
    unsigned long eff_off = SWP_OFFSET(swp) - sa->swap_off;
    struct swap_block_group *bg = &sa->block_groups[eff_off / MAX_BLOCK_GROUP_SIZE];
    u8 *map;
    u8 count;

    spin_lock(&bg->lock);

    map = bg->start + (eff_off % MAX_BLOCK_GROUP_SIZE);
    count = *map;
    spin_unlock(&bg->lock);

    return count;
}

void swap_unset_swapcache(swp_entry_t swp)
{
    struct swap_area *sa = swap_areas[SWP_TYPE(swp)];
    unsigned long eff_off = SWP_OFFSET(swp) - sa->swap_off;
    struct swap_block_group *bg = &sa->block_groups[eff_off / MAX_BLOCK_GROUP_SIZE];
    u8 *map;
    u8 count;

    spin_lock(&bg->lock);

    map = bg->start + (eff_off % MAX_BLOCK_GROUP_SIZE);
    count = *map & ~SWAP_MAP_SWAPCACHE;
    if (count == 0)
        __swap_add_counter(-1);
    *map = count;
    spin_unlock(&bg->lock);
}

void __swap_inc_map(swp_entry_t entry)
{
    struct swap_area *sa = swap_areas[SWP_TYPE(entry)];
    unsigned long eff_off = SWP_OFFSET(entry) - sa->swap_off;
    struct swap_block_group *bg = &sa->block_groups[eff_off / MAX_BLOCK_GROUP_SIZE];
    u8 *map;

    spin_lock(&bg->lock);

    map = bg->start + (eff_off % MAX_BLOCK_GROUP_SIZE);
    if (!WARN_ON_ONCE((*map & SWAP_MAX_USAGE) == SWAP_MAX_USAGE))
        *map = *map + 1;
    spin_unlock(&bg->lock);
}

void swap_inc_map(struct page *page)
{
    __swap_inc_map(swpval_to_swp_entry(page->priv));
}

void dump_page(struct page *page);

static int swap_add_to_swapcache(struct page *page)
{
    struct page *result;
    swp_entry_t entry = swpval_to_swp_entry(page->priv);
    struct vm_object *obj = swap_spaces[SWP_TYPE(entry)];
    DCHECK(obj != NULL);

    page_ref(page);
    page_set_uptodate(page);
    result = vmo_add_page_safe(SWP_OFFSET(entry) << PAGE_SHIFT, page, obj);
    if (!result)
    {
        page_unref(page);
        return -ENOMEM;
    }

    /* WARN if a page was stale in the swap cache */
    if (WARN_ON(result != page))
    {
        pr_warn("swap: swap space %lu had a stale swapcache entry at %lx (%p vs %p)\n",
                SWP_TYPE(entry), SWP_OFFSET(entry), result, page);
        dump_page(result);
        pr_warn("swap: swap map entry %hhx\n", swap_get_map(entry));
        return -EINVAL;
    }
    return 0;
}

/**
 * @brief Add a page to swap
 *
 * Add a page to swap (and the swap cache) and set PAGE_FLAG_SWAP.
 * @param page Page to start swapping out
 * @return 0 on success, negative error numbers
 */
int swap_add(struct page *page)
{
    int err;
    DCHECK_PAGE(page_locked(page), page);
    if (WARN_ON_ONCE(page_mapcount(page) > SWAP_MAX_USAGE))
    {
        /* We do not support more than MAX_USAGE maps just yet. */
        return -EINVAL;
    }

    err = swap_allocate(page);
    if (err < 0)
        return err;
    err = swap_add_to_swapcache(page);
    if (err)
    {
        swap_put_page(page);
        page_clear_swap(page);
        return err;
    }

    return 0;
}

struct vm_object *folio_vmobj(struct folio *folio)
{
    struct vm_object *obj = folio->owner;
    if (folio_test_swap(folio))
    {
        obj = swap_spaces[SWP_TYPE(swpval_to_swp_entry(folio->priv))];
        WARN_ON(!obj);
    }
    else if (folio_test_anon(folio))
        obj = NULL;
    return obj;
}

struct vm_object *page_vmobj(struct page *page)
{
    return folio_vmobj(page_folio(page));
}

unsigned long page_pgoff(struct page *page)
{
    if (page_test_swap(page))
        return SWP_OFFSET(swpval_to_swp_entry(page->priv));
    return page->pageoff;
}

static void swap_writepage_end(struct bio_req *req)
{
    struct page *page = req->vec[0].page;
    page_end_writeback(page);
}

static ssize_t swap_writepage(struct vm_object *vm_obj, struct page *page, size_t off)
    REQUIRES(page) RELEASE(page)
{
    int err;
    struct swap_area *sa = vm_obj->priv;
    struct bio_req *bio = bio_alloc(GFP_NOIO, 1);
    if (!bio)
    {
        err = -ENOMEM;
        goto err_unlock;
    }

    page_start_writeback(page);

    bio->sector_number = off / bdev_sector_size(sa->bdev);
    bio_push_pages(bio, page, 0, PAGE_SIZE);
    bio->b_end_io = swap_writepage_end;
    bio->flags = BIO_REQ_WRITE_OP;

    err = bio_submit_request(sa->bdev, bio);
    if (err < 0)
    {
        bio_put(bio);
        page_end_writeback(page);
        goto err_unlock;
    }
    bio_put(bio);

    unlock_page(page);

    return PAGE_SIZE;
err_unlock:
    unlock_page(page);
    return err;
}

static int swap_readpage(struct vm_object *obj, swp_entry_t swp, struct page *page) REQUIRES(page)
    RELEASE(page)
{
    int err;
    struct swap_area *sa = obj->priv;
    struct bio_req *bio = bio_alloc(GFP_NOIO, 1);
    if (!bio)
    {
        err = -ENOMEM;
        goto err_unlock;
    }

    bio->sector_number = SWP_OFFSET(swp) * (PAGE_SIZE / bdev_sector_size(sa->bdev));
    bio_push_pages(bio, page, 0, PAGE_SIZE);
    bio->flags = BIO_REQ_READ_OP;

    err = bio_submit_req_wait(sa->bdev, bio);
    bio_put(bio);
    if (err < 0)
        goto err_unlock;

    page_set_uptodate(page);
    unlock_page(page);
    return 0;
err_unlock:
    unlock_page(page);
    return err;
}

static struct page *swap_cache_find(struct vm_object *obj, swp_entry_t swp)
{
    struct page *p;
    vmo_status_t vst = vmo_get(obj, SWP_OFFSET(swp) << PAGE_SHIFT, 0, &p);
    if (vst != VMO_STATUS_OK)
        return NULL;
    return p;
}

static struct page *swap_read_from_storage(swp_entry_t swp, struct vm_object *obj, bool *created)
{
    struct page *page, *page2;
    int err;
    page = alloc_page(PAGE_ALLOC_NO_ZERO | GFP_KERNEL);
    if (!page)
        return ERR_PTR(-ENOMEM);
    /* Insert the page into the swap cache, _locked_. swap_cache_find callers should never observe
     * a locked, !UPTODATE page. Unless SIGBUS. */
    lock_page(page);
    page_ref(page);
    page_set_swap(page);
    page->priv = swp.swp;

    page2 = vmo_add_page_safe(SWP_OFFSET(swp) << PAGE_SHIFT, page, obj);
    if (page2 != page)
    {
        unlock_page(page);
        page_clear_swap(page);
        if (!page2)
            page_unref(page);
        page_unref(page);
        if (!page2)
            return ERR_PTR(-ENOMEM);
        return page2;
    }

    *created = true;
    page_set_anon(page);
    page_add_lru(page);

    /* page locked. Read it in. */
    err = swap_readpage(obj, swp, page);
    if (err < 0)
        return ERR_PTR(err);
    /* page unlocked */
    return page;
}

static void swap_cache_remove(struct vm_object *obj, struct page *page)
{
    DCHECK_PAGE(page_test_swap(page), page);
    DCHECK_PAGE(page_locked(page), page);
    swp_entry_t entry = swpval_to_swp_entry(page->priv);

    /* We can only get here if refcount = 2 (ours and the swap cache's). As such would imply from
     * swap_map's ref == 0. If we fail to remove, someone holds a reference to it (probably
     * reclaim?). as such don't clear swap nor put final. */
    if (!vm_obj_remove_page(obj, page))
        return;
    page_clear_swap(page);
    swap_final_put(entry);
    /* Refs were previously frozen, add one ref for "us" */
    page_ref_unfreeze(page, 1);
}

static int do_protnone(swp_entry_t swp, struct vm_pf_context *context)
{
    int err = -ENOMEM;
    struct vm_area_struct *vma = context->entry;
    u64 phys;
    struct spinlock *lock;

    phys = pte_addr(context->oldpte);
    err = pgtable_prealloc(vma->vm_mm, context->vpage);
    if (err < 0)
        return err;

    err = 0;
    pte_t *ptep = ptep_get_locked(vma->vm_mm, context->vpage, &lock);
    if (ptep->pte != context->oldpte.pte)
        goto out;
    pgprot_t pgprot = calc_pgprot(phys, vma->vm_flags & ~VM_WRITE);
    set_pte(ptep, pte_mkpte(phys, pgprot));
out:
    spin_unlock(lock);
    return err;
}

int do_swap_page(struct vm_pf_context *context) NO_THREAD_SAFETY_ANALYSIS
{
    struct vm_area_struct *vma = context->entry;
    swp_entry_t swp = pte_to_swp_entry(context->oldpte);
    struct vm_object *obj = swap_spaces[SWP_TYPE(swp)];
    struct page *page;
    bool created_page = false;
    int err;

    if (pte_protnone(context->oldpte))
        return do_protnone(swp, context);

    if (WARN_ON_ONCE(!obj))
    {
        pr_err("Bad swap entry %016lx\n", swp.swp);
        return -EINVAL;
    }

    page = swap_cache_find(obj, swp);
    if (!page)
    {
        page = swap_read_from_storage(swp, obj, &created_page);
        if (IS_ERR(page))
        {
            err = PTR_ERR(page);
            goto err;
        }
    }
    /* The page lock is essential here and protects against many funny scenarios. For instance,
     * let's imagine the following scenario: Reclaim finds page (mapped 2 times). swap_add allocates
     * swap space and adds it to the swap cache. rmap try_to_unmap unmaps pte 1. pte 1 faults,
     * do_swap_page sees swap_map-- == 0 and whacks the page from the swap cache. Then pte2 is
     * unmapped, but the page is no longer swap, and corruption ensues. This is all stopped by
     * reclaim holding the page lock. */

    lock_page(page);
    if (created_page)
    {
        page_set_anon(page);
        page->pageoff = context->vpage;
        page->owner = (struct vm_object *) vma->anon_vma;
        WARN_ON(!vma->anon_vma);
    }

    if (!page_test_uptodate(page))
    {
        err = -EIO;
        goto err_unlock;
    }

    if (swap_put_page(page))
        swap_cache_remove(obj, page);
    if (!vm_map_page(vma->vm_mm, context->vpage, (u64) page_to_phys(page),
                     context->page_rwx & ~VM_READ, vma))
    {
        err = -ENOMEM;
        goto err_unlock;
    }

    unlock_page(page);
    page_unref(page);
    return VM_FAULT_MAJOR;
err_unlock:
    unlock_page(page);
err:
    pr_err("Error swapping in entry %016lx (%04lx:%016lx): %d\n", swp.swp, SWP_TYPE(swp),
           SWP_OFFSET(swp), err);
    context->info->signal = err == -EIO ? SIGBUS : SIGSEGV;
    return err;
}
