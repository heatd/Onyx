/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _VIRTIO_HPP_
#define _VIRTIO_HPP

#include <stdint.h>
#include <stddef.h>

#include <onyx/portio.h>
#include <onyx/array.h>
#include <onyx/vector.h>
#include <onyx/smart.h>
#include <onyx/slice.hpp>
#include <onyx/condvar.h>
#include <onyx/bitmap.h>
#include <onyx/pair.hpp>

#include <pci/pci.h>

#include "virtio_pci.hpp"

#define MPRINTF(...)	printf("virtio: " __VA_ARGS__)


namespace virtio
{

enum network_registers
{
	mac_base = 0,
	status = 6,
	max_virtqueue_pairs = 8,
	mtu = 10,
	speed = 12,
	duplex = 16
};

enum network_features
{
	csum = 0,
	guest_csum = 1,
	ctrl_guest_offloads = 2,
	feature_mtu = 3,
	mac = 5,
	guest_tso4 = 7,
	guet_tso6 = 8,
	guest_ecn = 9,
	guest_ufo = 10,
	host_tso4 = 11,
	host_tso6 = 12,
	host_ecn = 13,
	host_ufo = 14,
	merge_rxbuf = 15,
	feature_status = 16,
	ctrl_vq = 17,
	ctrl_rx = 18,
	ctrl_vlan = 19,
	guest_announce = 21,
	feature_mq = 22,
	ctrl_mac_addr = 23,
	rsc_ext = 61,
	standby = 62
};

/* Means that the descriptor continues via the next field */
#define VIRTQ_DESC_F_NEXT			(1 << 0)
/* Buffer is device-write only */
#define VIRTQ_DESC_F_WRITE			(1 << 1)
/* Buffer contains a list of buffer descriptors */
#define VIRTQ_DESC_F_INDIRECT		(1 << 2)

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

class vdev;
class virtq;

class virtio_buf
{
public:
	unsigned long addr;
	size_t length;
	bool write;
	uint16_t index;
	virtq *vq;
	struct list_head buf_list_memb;

	virtio_buf(unsigned long paddr, size_t length, virtq *v) : addr{paddr}, length{length}, write{false},
															   index{0}, vq{v}
	{ INIT_LIST_HEAD(&buf_list_memb); }

	~virtio_buf() {}
};

class virtio_buf_list
{
private:
	void tear_down_bufs();
public:
	struct list_head buf_list_head;
	virtq *vq;
	size_t nr_elems;

	virtio_buf_list(virtq *v) : buf_list_head{}, vq(v), nr_elems{}
	{
		INIT_LIST_HEAD(&buf_list_head);
	}

	~virtio_buf_list()
	{
		tear_down_bufs();
	}

	bool prepare(void *addr, size_t length, bool writeable);
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
	virtual bool put_buffer(virtio_buf_list& bufs) = 0;
	virtual void notify() = 0;
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
public:
	virtq_split(vdev *dev, unsigned int qsize, unsigned int nr) : virtq{dev, nr}, vq_pages{nullptr},
		queue_size{qsize}, descs{nullptr},
		avail{nullptr}, used{nullptr}, eff_queue_notify_off{0}
	{ avail_descs = get_queue_size(); }
	
	~virtq_split() {}
	
	bool init() override;
	bool put_buffer(virtio_buf_list& bufs) override;
	
	unsigned int get_queue_size() override
	{
		return queue_size;
	}

	uint16_t prepare_descriptors(virtio_buf_list& bufs);

	void notify() override;
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
public:
	vdev(struct pci_device *dev) : dev(dev), bars{}, structures{} {}
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

	bool has_feature(unsigned long feature);

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
};

struct virtio_net_hdr
{ 
#define VIRTIO_NET_HDR_F_NEEDS_CSUM    1 
#define VIRTIO_NET_HDR_F_DATA_VALID    2 
#define VIRTIO_NET_HDR_F_RSC_INFO      4 
	uint8_t flags; 
#define VIRTIO_NET_HDR_GSO_NONE        0 
#define VIRTIO_NET_HDR_GSO_TCPV4       1 
#define VIRTIO_NET_HDR_GSO_UDP         3 
#define VIRTIO_NET_HDR_GSO_TCPV6       4 
#define VIRTIO_NET_HDR_GSO_ECN      0x80 
	uint8_t gso_type; 
	uint16_t hdr_len; 
	uint16_t gso_size; 
	uint16_t csum_start; 
	uint16_t csum_offset; 
	uint16_t num_buffers; 
};

class network_vdev : public vdev
{
private:
	void get_mac(cul::slice<uint8_t, 6>& mac_buf);
public:
	network_vdev(struct pci_device *d) : vdev(d) {}
	~network_vdev() {}
	
	bool perform_subsystem_initialization() override;
};

class gpu_vdev : public vdev
{
public:
	gpu_vdev(struct pci_device *d) : vdev(d) {}
	~gpu_vdev() {}
	
	bool perform_subsystem_initialization() override
	{
		return true;
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

};

#endif