/*
 * Copyright (c) 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/* Stubs for the Linux compat layer. Everything in here is unimplemented and will explode if
 * called; as bits and pieces get properly implemented, they should be removed from this file and
 * moved into a proper implementation file.
 */

#include <onyx/assert.h>

#include <drm/drm_sysfs.h>
#include <drm/drm_utils.h>
#include <linux/device.h>
#include <linux/dma-buf.h>
#include <linux/dma-fence-chain.h>
#include <linux/dma-fence-unwrap.h>
#include <linux/dma-fence.h>
#include <linux/dma-resv.h>
#include <linux/fs.h>
#include <linux/hdmi.h>
#include <linux/i2c.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/list_sort.h>
#include <linux/mm.h>
#include <linux/pci.h>
#include <linux/pseudo_fs.h>
#include <linux/scatterlist.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/string.h>
#include <linux/time64.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/ww_mutex.h>

/* Variables that should be provided by proper subsystem code */

/* The jiffies counter. Not hooked up to the timer tick yet. */
unsigned long jiffies;

/* Root of the iomem resource tree. Empty for now. */
struct resource iomem_resource = {
    .start = 0,
    .end = -1,
    .name = "PCI mem",
};

#ifdef __x86_64__
/* Set up with a sane default cacheline size; should be filled in by CPU detection code. */
struct cpuinfo_x86 boot_cpu_data = {
    .x86_clflush_size = 64,
};
#endif

/* This one is a real definition (and not a stub) - dma_resv objects all share a ww_class. */
DEFINE_WD_CLASS(reservation_ww_class);

/* device model */

int __devm_add_action_or_reset(struct device *dev, void (*action)(void *), void *data,
                               const char *name)
{
    CHECK(0);
    return -ENOSYS;
}

void devm_release_action(struct device *dev, void (*action)(void *), void *data)
{
    CHECK(0);
}

struct device *get_device(struct device *dev)
{
    CHECK(0);
    return NULL;
}

void put_device(struct device *dev)
{
    CHECK(0);
}

int device_add(struct device *dev)
{
    CHECK(0);
    return -ENOSYS;
}

void device_del(struct device *dev)
{
    CHECK(0);
}

bool device_is_registered(struct device *dev)
{
    CHECK(0);
    return false;
}

const char *dev_name(const struct device *dev)
{
    CHECK(0);
    return NULL;
}

/* dma-buf */

struct dma_buf_attachment *dma_buf_attach(struct dma_buf *dmabuf, struct device *dev)
{
    CHECK(0);
    return ERR_PTR(-ENOSYS);
}

void dma_buf_detach(struct dma_buf *dmabuf, struct dma_buf_attachment *attach)
{
    CHECK(0);
}

struct dma_buf *dma_buf_export(const struct dma_buf_export_info *exp_info)
{
    CHECK(0);
    return ERR_PTR(-ENOSYS);
}

struct dma_buf *dma_buf_get(int fd)
{
    CHECK(0);
    return ERR_PTR(-ENOSYS);
}

void dma_buf_put(struct dma_buf *dmabuf)
{
    CHECK(0);
}

struct sg_table *dma_buf_map_attachment_unlocked(struct dma_buf_attachment *attach,
                                                 enum dma_data_direction direction)
{
    CHECK(0);
    return ERR_PTR(-ENOSYS);
}

void dma_buf_unmap_attachment_unlocked(struct dma_buf_attachment *attach, struct sg_table *sg_table,
                                       enum dma_data_direction direction)
{
    CHECK(0);
}

/* dma-fence */

void dma_fence_init(struct dma_fence *fence, const struct dma_fence_ops *ops, spinlock_t *lock,
                    u64 context, u64 seqno)
{
    CHECK(0);
}

int dma_fence_signal(struct dma_fence *fence)
{
    CHECK(0);
    return -ENOSYS;
}

int dma_fence_signal_timestamp(struct dma_fence *fence, ktime_t timestamp)
{
    CHECK(0);
    return -ENOSYS;
}

int dma_fence_add_callback(struct dma_fence *fence, struct dma_fence_cb *cb, dma_fence_func_t func)
{
    CHECK(0);
    return -ENOSYS;
}

bool dma_fence_remove_callback(struct dma_fence *fence, struct dma_fence_cb *cb)
{
    CHECK(0);
    return false;
}

void dma_fence_set_deadline(struct dma_fence *fence, ktime_t deadline)
{
    CHECK(0);
}

struct dma_fence *dma_fence_get_stub(void)
{
    CHECK(0);
    return ERR_PTR(-ENOSYS);
}

struct dma_fence *dma_fence_allocate_private_stub(ktime_t timestamp)
{
    CHECK(0);
    return ERR_PTR(-ENOSYS);
}

u64 dma_fence_context_alloc(unsigned int num)
{
    CHECK(0);
    return 0;
}

/* dma-fence-chain */

static const char *dma_fence_chain_stub_name(struct dma_fence *fence)
{
    return "unimplemented";
}

const struct dma_fence_ops dma_fence_chain_ops = {
    .get_driver_name = dma_fence_chain_stub_name,
    .get_timeline_name = dma_fence_chain_stub_name,
};

struct dma_fence *dma_fence_chain_walk(struct dma_fence *fence)
{
    CHECK(0);
    return NULL;
}

int dma_fence_chain_find_seqno(struct dma_fence **pfence, uint64_t seqno)
{
    CHECK(0);
    return -ENOSYS;
}

void dma_fence_chain_init(struct dma_fence_chain *chain, struct dma_fence *prev,
                          struct dma_fence *fence, uint64_t seqno)
{
    CHECK(0);
}

/* dma-fence-unwrap */

struct dma_fence *__dma_fence_unwrap_merge(unsigned int num_fences, struct dma_fence **fences,
                                           struct dma_fence_unwrap *cursors)
{
    CHECK(0);
    return NULL;
}

/* dma-resv */

void dma_resv_init(struct dma_resv *obj)
{
    CHECK(0);
}

void dma_resv_fini(struct dma_resv *obj)
{
    CHECK(0);
}

long dma_resv_wait_timeout(struct dma_resv *obj, enum dma_resv_usage usage, bool intr,
                           unsigned long timeout)
{
    CHECK(0);
    return -ENOSYS;
}

bool dma_resv_test_signaled(struct dma_resv *obj, enum dma_resv_usage usage)
{
    CHECK(0);
    return false;
}

/* ww_mutex */

int ww_mutex_lock(struct ww_mutex *ww, struct ww_acquire_ctx *ctx)
{
    CHECK(0);
    return -ENOSYS;
}

int ww_mutex_lock_interruptible(struct ww_mutex *ww, struct ww_acquire_ctx *ctx)
{
    CHECK(0);
    return -ENOSYS;
}

int ww_mutex_trylock(struct ww_mutex *ww, struct ww_acquire_ctx *ctx)
{
    CHECK(0);
    return -ENOSYS;
}

void ww_mutex_unlock(struct ww_mutex *ww)
{
    CHECK(0);
}

/* kthread_worker */

void kthread_flush_worker(struct kthread_worker *kw)
{
    CHECK(0);
}

void kthread_destroy_worker(struct kthread_worker *kw)
{
    CHECK(0);
}

bool kthread_queue_work(struct kthread_worker *kw, struct kthread_work *work)
{
    CHECK(0);
    return false;
}

bool kthread_cancel_work_sync(struct kthread_work *work)
{
    CHECK(0);
    return false;
}

void kthread_flush_work(struct kthread_work *work)
{
    CHECK(0);
}

struct kthread_worker *kthread_create_worker(unsigned int flags, const char *namefmt, ...)
{
    CHECK(0);
    return ERR_PTR(-ENOSYS);
}

/* timers */

int mod_timer(struct timer_list *timer, unsigned long expires)
{
    CHECK(0);
    return -ENOSYS;
}

int timer_delete_sync(struct timer_list *timer)
{
    CHECK(0);
    return -ENOSYS;
}

struct timespec64 ns_to_timespec64(s64 nsec)
{
    struct timespec64 ts = {};
    CHECK(0);
    return ts;
}

/* fs */

#define DEV_REGISTER_STATIC_DEV (1 << 0)

int c_dev_register_chardevs(dev_t dev, unsigned int nr_devices, unsigned int flags,
                            const struct file_ops *fops, const char *name);

int register_chrdev(unsigned int major, const char *name, const struct file_operations *fops)
{
    unsigned int flags = 0;

    if (!major)
        flags |= DEV_REGISTER_STATIC_DEV;

    return c_dev_register_chardevs(MKDEV(major, 0), 1, flags, fops, name);
}

void unregister_chrdev(unsigned int major, const char *name)
{
    pr_warn_once("%s: unimplemented\n", __func__);
}

struct pseudo_fs_context *init_pseudo(struct fs_context *fc, unsigned long magic)
{
    CHECK(0);
    return ERR_PTR(-ENOSYS);
}

void kill_anon_super(struct super_block *sb)
{
    CHECK(0);
}

int simple_pin_fs(struct file_system_type *type, struct vfsmount **mount, int *count)
{
    CHECK(0);
    return -ENOSYS;
}

int simple_release_fs(struct vfsmount **mount, int *count)
{
    CHECK(0);
    return -ENOSYS;
}

struct inode *alloc_anon_inode(struct super_block *s)
{
    CHECK(0);
    return ERR_PTR(-ENOSYS);
}

struct fd linux_fdget(unsigned int fd)
{
    struct fd f = {};
    CHECK(0);
    return f;
}

/* shmem */

struct file *shmem_file_setup(const char *name, loff_t size, unsigned long flags)
{
    CHECK(0);
    return ERR_PTR(-ENOSYS);
}

struct file *shmem_file_setup_with_mnt(struct vfsmount *mnt, const char *name, loff_t size,
                                       unsigned long flags)
{
    CHECK(0);
    return ERR_PTR(-ENOSYS);
}

struct folio *shmem_read_folio_gfp(struct address_space *mapping, pgoff_t index, gfp_t gfp)
{
    CHECK(0);
    return ERR_PTR(-ENOSYS);
}

/* mm */

void check_move_unevictable_folios(struct folio_batch *batch)
{
    CHECK(0);
}

size_t ksize(void *ptr)
{
    CHECK(0);
    return 0;
}

/* strings and misc lib */

char *kstrdup(const char *str, gfp_t gfp)
{
    CHECK(0);
    return NULL;
}

const char *kstrdup_const(const char *s, gfp_t gfp)
{
    CHECK(0);
    return NULL;
}

void kfree_const(const void *x)
{
    CHECK(0);
}

void *memdup_user_nul(const void __user *src, size_t len)
{
    CHECK(0);
    return ERR_PTR(-ENOSYS);
}

void *memdup_array_user(const void __user *src, size_t n, size_t size)
{
    CHECK(0);
    return ERR_PTR(-ENOSYS);
}

long simple_strtol(const char *cp, char **endp, unsigned int base)
{
    CHECK(0);
    return 0;
}

void sort(void *base, size_t num, size_t size, cmp_func_t cmp_func, swap_func_t swap_func)
{
    CHECK(0);
}

void list_sort(void *priv, struct list_head *head, list_cmp_func_t cmp)
{
    CHECK(0);
}

/* io */

void memcpy_fromio(void *dst, const volatile void __iomem *src, size_t count)
{
    CHECK(0);
}

void memcpy_toio(volatile void __iomem *dst, const void *src, size_t count)
{
    CHECK(0);
}

/* scatterlist */

void __sg_page_iter_start(struct sg_page_iter *piter, struct scatterlist *sglist,
                          unsigned int nents, unsigned long pgoffset)
{
    CHECK(0);
}

bool __sg_page_iter_next(struct sg_page_iter *piter)
{
    CHECK(0);
    return false;
}

void __sg_page_iter_dma_start(struct sg_dma_page_iter *piter, struct scatterlist *sglist,
                              unsigned int nents, unsigned long pgoffset)
{
    CHECK(0);
}

bool __sg_page_iter_dma_next(struct sg_dma_page_iter *piter)
{
    CHECK(0);
    return false;
}

int sg_alloc_table_from_pages_segment(struct sg_table *sgt, struct page **pages,
                                      unsigned int n_pages, unsigned int offset, unsigned long size,
                                      unsigned int max_segment, gfp_t gfp_mask)
{
    CHECK(0);
    return -ENOSYS;
}

/* i2c and HDMI */

int i2c_transfer(struct i2c_adapter *adap, struct i2c_msg *msgs, int num)
{
    CHECK(0);
    return -ENOSYS;
}

void hdmi_avi_infoframe_init(struct hdmi_avi_infoframe *frame)
{
    CHECK(0);
}

int hdmi_vendor_infoframe_init(struct hdmi_vendor_infoframe *frame)
{
    CHECK(0);
    return -ENOSYS;
}

/* PCI */

unsigned int pci_domain_nr(struct pci_bus *bus)
{
    CHECK(0);
    return 0;
}

/* DRM sysfs. Declared in drivers/gpu/drm/drm_internal.h (not includable from here) and
 * include/drm/drm_sysfs.h.
 */
struct drm_minor;

int drm_sysfs_init(void);
void drm_sysfs_destroy(void);
struct device *drm_sysfs_minor_alloc(struct drm_minor *minor);
int drm_sysfs_connector_add(struct drm_connector *connector);
int drm_sysfs_connector_add_late(struct drm_connector *connector);
void drm_sysfs_connector_remove_early(struct drm_connector *connector);
void drm_sysfs_connector_remove(struct drm_connector *connector);
void drm_sysfs_lease_event(struct drm_device *dev);

int drm_sysfs_init(void)
{
    return 0;
}

void drm_sysfs_destroy(void)
{
    CHECK(0);
}

struct device *drm_sysfs_minor_alloc(struct drm_minor *minor)
{
    CHECK(0);
    return ERR_PTR(-ENOSYS);
}

int drm_sysfs_connector_add(struct drm_connector *connector)
{
    CHECK(0);
    return -ENOSYS;
}

int drm_sysfs_connector_add_late(struct drm_connector *connector)
{
    CHECK(0);
    return -ENOSYS;
}

void drm_sysfs_connector_remove_early(struct drm_connector *connector)
{
    CHECK(0);
}

void drm_sysfs_connector_remove(struct drm_connector *connector)
{
    CHECK(0);
}

void drm_sysfs_lease_event(struct drm_device *dev)
{
    CHECK(0);
}

void drm_sysfs_hotplug_event(struct drm_device *dev)
{
    CHECK(0);
}

void drm_sysfs_connector_hotplug_event(struct drm_connector *connector)
{
    CHECK(0);
}

void drm_sysfs_connector_property_event(struct drm_connector *connector,
                                        struct drm_property *property)
{
    CHECK(0);
}

/* DRM misc */

int drm_get_panel_orientation_quirk(int width, int height)
{
    CHECK(0);
    return -ENOSYS;
}

bool flush_work(struct work_struct *work)
{
    CHECK(0);
    return false;
}

void destroy_workqueue(struct workqueue_struct *wq)
{
    WARN_ON_ONCE(1);
}
