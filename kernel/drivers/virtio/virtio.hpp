/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _VIRTIO_HPP_
#define _VIRTIO_HPP_

#include <stdint.h>
#include <stddef.h>

#include <onyx/portio.h>
#include <onyx/array.h>
#include <onyx/vector.h>
#include <onyx/memory.hpp>
#include <onyx/slice.hpp>
#include <onyx/condvar.h>
#include <onyx/bitmap.h>
#include <onyx/pair.hpp>
#include <onyx/irq.h>

#include <onyx/net/netif.h>
#include <onyx/packetbuf.h>
#include <onyx/pair.hpp>

#include <pci/pci.h>

#include "virtio_pci.hpp"

#define MPRINTF(...)	printf("virtio: " __VA_ARGS__)


namespace virtio
{

/* Device-independent features*/
enum device_features
{
	ring_indirect_desc = 28,
	ring_event_idx = 29,
	version_1 = 32,
	access_platform = 33,
	ring_packed = 34,
	in_order = 35,
	order_platform = 36,
	sr_iov = 37,
	notification_data = 38
};

/* Means that the descriptor continues via the next field */
#define VIRTQ_DESC_F_NEXT			(1 << 0)
/* Buffer is device-write only */
#define VIRTQ_DESC_F_WRITE			(1 << 1)
/* Buffer contains a list of buffer descriptors */
#define VIRTQ_DESC_F_INDIRECT		(1 << 2)

#pragma GCC diagnostic push
#pragma GCC diagnostic warning "-Wpadded"

struct virtq_desc
{
	/* physical address */
	uint64_t paddr;
	uint32_t length;
	uint16_t flags;
	uint16_t next;
};

#define VIRTQ_AVAIL_F_NO_INTERRUPT		(1 << 0)
struct virtq_avail
{
	uint16_t flags;
	uint16_t idx;
	uint16_t ring[];
	/* At the end there's a uint16_t used_event if VIRTIO_F_EVENT_IDX */
};

struct virtq_used_elem
{
	/* uint32_t is used here for padding purposes - the value is actually 16-bit */
	uint32_t id;
	uint32_t length;
};

struct virtq_used
{
	uint16_t flags;
	uint16_t idx;
	struct virtq_used_elem ring[];
};

#pragma GCC diagnostic pop

class vdev;
class virtq;

class virtio_buf
{
public:
	unsigned long addr;
	size_t length;
	bool write;
	uint16_t index;
	struct list_head buf_list_memb;

	virtio_buf(unsigned long paddr, size_t length) : addr{paddr}, length{length}, write{false},
															   index{0}
	{ INIT_LIST_HEAD(&buf_list_memb); }

	~virtio_buf() {}
};

class virtio_buf_list
{
private:
	void tear_down_bufs();
public:
	struct list_head buf_list_head;
	const unique_ptr<virtq> &vq;
	size_t nr_elems;

	virtio_buf_list(const unique_ptr<virtq> &v) : buf_list_head{}, vq(v), nr_elems{}
	{
		INIT_LIST_HEAD(&buf_list_head);
	}

	~virtio_buf_list()
	{
		tear_down_bufs();
	}

	bool prepare(const void *addr, size_t length, bool writeable);
};

class virtq
{
protected:
	vdev *device;	
	unsigned int nr;
	/* Descriptor bitmap */
	Bitmap<0, false> desc_bitmap;
	/* Number of available descriptors - can only be touched when desc_alloc_lock is held */
	size_t avail_descs;
	/* Descriptor allocation lock */
	Spinlock desc_alloc_lock;
public:
	bool allocate_descriptors(virtio_buf_list& buf);
	virtual unsigned int get_queue_size() = 0;
	virtq(vdev *dev, unsigned int nr) : device{dev}, nr{nr}, desc_bitmap{},
                                        avail_descs(), desc_alloc_lock{} {}
	virtual ~virtq() {}
	virtual bool init() = 0;
	virtual bool put_buffer(virtio_buf_list& bufs, bool notify = true) = 0;
	virtual void notify() = 0;
	virtual void handle_irq() = 0;
	unsigned int get_nr() const {return nr;}
	virtual cul::pair<unsigned long, size_t> get_buf_from_id(uint16_t id) const = 0;
};

class virtq_split : public virtq
{
private:
	struct page *vq_pages;
	unsigned int queue_size;
	/* Descriptor area */
	struct virtq_desc *descs;
	/* Driver area */
	struct virtq_avail *avail;
	/* Device area */
	struct virtq_used *used;
	/* Note: this has been calculated from queue_mult * queue_notify_off */
	unsigned long eff_queue_notify_off;
	/* The driver keeps track of the last used_idx in order to track progress for used buffers */
	unsigned int last_seen_used_idx;
public:
	virtq_split(vdev *dev, unsigned int qsize, unsigned int nr) : virtq{dev, nr}, vq_pages{nullptr},
		queue_size{qsize}, descs{nullptr},
		avail{nullptr}, used{nullptr}, eff_queue_notify_off{0}, last_seen_used_idx{0}
	{ avail_descs = get_queue_size(); }
	
	~virtq_split() {}
	
	bool init() override;
	bool put_buffer(virtio_buf_list& bufs, bool notify) override;
	
	unsigned int get_queue_size() override
	{
		return queue_size;
	}

	uint16_t prepare_descriptors(virtio_buf_list& bufs);

	void notify() override;

	void handle_irq() override;

	cul::pair<unsigned long, size_t> get_buf_from_id(uint16_t id) const override;
};

class virtio_structure
{
public:
	volatile void *bar;
	bool is_io_port;
	unsigned long offset;
	unsigned long length;
	bool initialized;
	uint32_t notify_off_mult;

	constexpr virtio_structure() : bar{nullptr}, is_io_port{false}, offset{0}, length{0}, initialized{false},
                         notify_off_mult{~0U} {}

	virtio_structure(const virtio_structure& s) = delete;
	virtio_structure& operator=(const virtio_structure& s) = delete;
	/* TODO: [[gnu::noinline]] and COMDAT sections(which
	 * is where these template functions get put) don't work well with mcount_loc...
	 * Until there's a fix, we can't do this. Sigh.
	*/
	/* TODO: Maybe it breaks if the template is ruled as not-inlinable by the compiler? Investigate. */
	template <typename T>
	//[[gnu::noinline]]
	T read(unsigned long off) const
	{
		unsigned long eoff = off + offset;
	
		if(is_io_port)
		{
			switch(sizeof(T))
			{
				case 1:
					return inb((uint16_t) (unsigned long) bar + eoff);
				case 2:
					return inw((uint16_t) (unsigned long) bar + eoff);
				case 4:
					return inl((uint16_t) (unsigned long) bar + eoff);
				case 8:
					__builtin_unreachable();
			}
		}
		else
		{
			auto p = reinterpret_cast<volatile T *>((uint8_t *) bar + eoff);
			return *p;
		}
	}

	template <typename T>
	//[[gnu::noinline]]
	void write(unsigned long off, T val)
	{
		unsigned long eoff = off + offset;
		if(is_io_port)
		{
			switch(sizeof(T))
			{
				case 1:
					outb((uint16_t) (unsigned long) bar + eoff, val);
					break;
				case 2:
					outw((uint16_t) (unsigned long) bar + eoff, val);
					break;
				case 4:
					outl((uint16_t) (unsigned long) bar + eoff, val);
					break;
				case 8:
					__builtin_unreachable();
			}
		}
		else
		{
			auto p = reinterpret_cast<volatile T *>((uint8_t *) bar + eoff);
			*p = val;
		}
	}

};

/* TODO: Hide pci_device (since it may or may not be a pci_device) with a virtual class */
class vdev
{
protected:
	struct pci_device *dev;
	void *bars[PCI_NR_BARS];
	virtio_structure structures[5];
	cul::vector<unique_ptr<virtq> > virtqueue_list;

	virtual bool supports_legacy()
	{
		return false;
	}

	bool do_device_independent_negotiation();

	uint64_t feature_cache[1];

	void cache_features();

	bool has_feature(unsigned long feature) const
	{
		assert(feature < 64);
		return feature_cache[0] & (1UL << feature);
	}

public:
	vdev(struct pci_device *dev) : dev(dev), bars{}, structures{}, feature_cache{} {}
	virtual ~vdev() {}
	vdev(const vdev& rhs) = delete;
	vdev(vdev&& rhs) = delete;
	
	vdev& operator=(const vdev& rhs) = delete;
	vdev& operator=(vdev&& rhs) = delete;

	virtio_structure& pci_common_cfg()
	{
		return structures[virtio::vendor_pci_cap::common - 1];
	}

	virtio_structure& device_cfg()
	{
		return structures[virtio::vendor_pci_cap::device - 1];
	}

	virtio_structure& notify_cfg()
	{
		return structures[virtio::vendor_pci_cap::notify - 1];
	}

	virtio_structure& isr_cfg()
	{
		return structures[virtio::vendor_pci_cap::isr - 1];
	}

	template <typename T>
	T read_config(unsigned long offset)
	{
		return pci_common_cfg().read<T>(offset);
	}

	template <typename T>
	void write_config(unsigned long offset, T val)
	{
		pci_common_cfg().write(offset, val);
	}

	template <typename T>
	T read(unsigned long offset)
	{
		return device_cfg().read<T>(offset);
	}

	template <typename T>
	void write(unsigned long offset, T val)
	{
		device_cfg().write(offset, val);
	}

	bool raw_has_feature(unsigned long feature);

	/* To be used by drivers to negotiate features */
	void signal_feature(unsigned long feature);

	/* Used to end feature negotiation */
	bool finish_feature_negotiation();

	bool perform_base_virtio_initialization();
	bool find_structures();
	void reset();
	virtual bool perform_subsystem_initialization() = 0;
	bool create_virtqueue(unsigned int nr, unsigned queue_size);
	uint16_t get_max_virtq_size(unsigned int nr);

	void finalise_driver_init();
	void set_failure();

	irqstatus_t handle_irq();

	void handle_vq_irq();

	virtual void handle_used_buffer(const virtq_used_elem &elem, const virtq *vq)
	{}

	const unique_ptr<virtq>& get_vq(int nr)
	{
		return virtqueue_list[nr];
	}
};

enum device_status : uint8_t
{
	acknowledge = (1 << 0),
	driver = (1 << 1),
	failed = (1 << 7),
	features_ok = (1 << 3),
	driver_ok = (1 << 2),
	vdev_needs_reset = (1 << 6)
};

#ifdef CONFIG_VIRTIO_NET
unique_ptr<vdev> create_network_device(pci_device *dev);
#endif
#ifdef CONFIG_VIRTIO_GPU
unique_ptr<vdev> create_gpu_device(pci_device *dev);
#endif
};

#endif
