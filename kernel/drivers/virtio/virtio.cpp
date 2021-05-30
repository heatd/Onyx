/*
* Copyright (c) 2018-2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <assert.h>

#include <onyx/driver.h>
#include <onyx/dev.h>
#include <onyx/acpi.h>
#include <onyx/memory.hpp>
#include <onyx/byteswap.h>
#include <onyx/compiler.h>
#include <onyx/dma.h>
#include <onyx/cpu.h>

#include <pci/pci.h>
#include "virtio.hpp"
#include "virtio_utils.hpp"


namespace virtio
{

const uint16_t subsystems[] =
{
	virtio::network_pci_subsys,
	virtio::block_pci_subsys
};

uint16_t get_virtio_devid(uint16_t device_id)
{
	bool transitional = device_id < pci_device_id_base;

	if(transitional)
	{
		uint16_t index = device_id - pci_device_id_base_transitional;
		if(sizeof(subsystems) / sizeof(subsystems[0]) <= index)
			return 0xffff;
		
		return subsystems[index];
	}

	return device_id - pci_device_id_base;
}

bool vdev::find_structures()
{
	size_t cap_off = 0;
	int instance_nr = 0;

	while((cap_off = dev->find_capability(PCI_CAP_ID_VENDOR, instance_nr)) != 0)
	{
		instance_nr++;
		uint8_t cfg_type = dev->read(cap_off + virtio::cfg_type_off, sizeof(uint8_t));
		uint8_t bar = dev->read(cap_off + virtio::bar_off, sizeof(uint8_t));
		uint32_t offset = dev->read(cap_off + virtio::offset_off, sizeof(uint32_t));
		uint32_t length = dev->read(cap_off + virtio::length_off, sizeof(uint32_t));
		pci::pci_bar bar_info;
	
		auto st = dev->get_bar(bar);

		if(st.has_error())
			return false;
		
		bar_info = st.value();

		auto *structure = &structures[cfg_type - 1];

		if(cfg_type == virtio::vendor_pci_cap::notify)
		{
			structure->notify_off_mult = dev->read(cap_off + virtio::notify_off_multiplier, sizeof(uint32_t));
		}

		if(structure->initialized)
		{
			/* Prefer mmio over io ports */
			if(bar_info.is_iorange && !structure->is_io_port)
				continue;
		}

		if(bar_info.is_iorange)
		{
			structure->is_io_port = true;
			structure->bar = reinterpret_cast<volatile void *>(bar_info.address);
		}
		else
		{
			void *mapping = bars[bar];
			
			if(!mapping)
			{
				/* Create a mapping of the bar */
				mapping = bars[bar] = dev->map_bar(bar, VM_NOCACHE);
				if(!mapping)
				{
					return false;
				}
			}

			structure->is_io_port = false;
			structure->bar = reinterpret_cast<volatile void *>(mapping);
		}

		structure->offset = offset;
		structure->length = length;
		structure->initialized = true;
	}

	return true;
}

void vdev::reset()
{
	pci_common_cfg().write<uint8_t>(pci_common_cfg::device_status, 0);
}

bool vdev::perform_base_virtio_initialization()
{
	if(!find_structures())
		return false;
	
	/* Initialization sequence as described in 3.1.1 */
	reset();

	pci_common_cfg().write(pci_common_cfg::device_status, device_status::acknowledge);
	
	auto r = pci_common_cfg().read<uint8_t>(pci_common_cfg::device_status);
	r |= device_status::driver;
	pci_common_cfg().write(pci_common_cfg::device_status, r);

	return true;
}

bool vdev::raw_has_feature(unsigned long feature)
{
	unsigned long dwords = feature / 32;
	unsigned long remainder = feature % 32;

	pci_common_cfg().write(device_feature_select, dwords);
	return pci_common_cfg().read<uint32_t>(device_feature) & (1 << remainder);
}

void vdev::cache_features()
{
	/* Right now, the max feature bit is 38, so the logic is quite simple, we just need to
	 * read two device feature dwords and or them together.
	 */

	uint32_t words[2];
	
	for(int i = 0; i < 2; i++)
	{
		pci_common_cfg().write(device_feature_select, i);
		words[i] = pci_common_cfg().read<uint32_t>(device_feature);
	}

	feature_cache[0] = static_cast<uint64_t>(words[1]) << 32 | words[0];
}

void vdev::signal_feature(unsigned long feature)
{
	unsigned long dwords = feature / 32;
	unsigned long remainder = feature % 32;

	pci_common_cfg().write(driver_feature_select, dwords);
	auto word = pci_common_cfg().read<uint32_t>(driver_feature);
	word |= (1 << remainder);
	pci_common_cfg().write<uint32_t>(driver_feature, word);
}

uint16_t vdev::get_max_virtq_size(unsigned int nr)
{
	write_config<uint16_t>(pci_common_cfg::queue_select, nr);
	return read_config<uint16_t>(pci_common_cfg::queue_size);
}

bool vdev::create_virtqueue(unsigned int nr, unsigned int queue_size)
{
	if(virtqueue_list.size() > nr)
	{
		/* Can't create two virtqueues at the same index */
		assert(virtqueue_list[nr] == nullptr);
	}

	if(virtqueue_list.size() <= nr)
	{
		/* Pre-reserve the list */
		virtqueue_list.reserve(nr + 1);
		virtqueue_list.set_nr_elems(nr + 1);
	}

	virtqueue_list[nr] = make_unique<virtq_split>(this, queue_size, nr);

	if(!virtqueue_list[nr])
		return false;
	

	if(!virtqueue_list[nr]->init())
	{
		virtqueue_list[nr].reset(nullptr);
		return false;
	}

	return true;
}

bool vdev::finish_feature_negotiation()
{
	auto r = pci_common_cfg().read<uint8_t>(pci_common_cfg::device_status);
	r |= device_status::features_ok;
	pci_common_cfg().write(pci_common_cfg::device_status, r);

	if(pci_common_cfg().read<uint8_t>(pci_common_cfg::device_status) & device_status::features_ok)
	{
		cache_features();
		return true;
	}

	/* If features ok isn't set anymore, the features we selected are not supported */
	return false;
}

void vdev::finalise_driver_init()
{
	auto st = pci_common_cfg().read<uint8_t>(pci_common_cfg::device_status);
	st |= device_status::driver_ok;
	pci_common_cfg().write<uint8_t>(pci_common_cfg::device_status, st);
}

void vdev::set_failure()
{
	auto st = pci_common_cfg().read<uint8_t>(pci_common_cfg::device_status);
	st |= device_status::failed;
	pci_common_cfg().write<uint8_t>(pci_common_cfg::device_status, st);
}

bool vdev::do_device_independent_negotiation()
{
	if(raw_has_feature(device_features::version_1))
	{
		signal_feature(device_features::version_1);
	}
	else
	{
		if(!supports_legacy())
			return false;
	}

	if(raw_has_feature(device_features::ring_indirect_desc))
	{
		signal_feature(device_features::ring_indirect_desc);
	}

	return true;
}

bool virtq_split::init()
{
	/* Described in section 2.6 - keep in mind that we align the
	 * previous virtq segment's size to the next segment's alignment(also described in 2.6)
	*/
	size_t descriptor_table_length = ALIGN_TO(queue_size * sizeof(virtq_desc), 2);
	size_t avail_ring_length = ALIGN_TO(queue_size * sizeof(uint16_t) + 4, 4);
	size_t used_ring_length = queue_size * sizeof(virtq_used_elem)
                              + sizeof(uint16_t) * 2;
	size_t total_pages = vm_size_to_pages(descriptor_table_length
                         + avail_ring_length + used_ring_length);
	
	desc_bitmap.SetSize(queue_size);
	if(!desc_bitmap.AllocateBitmap())
		return false;
	
	if(!completions.reserve(queue_size))
		return false;
	
	completions.set_nr_elems(queue_size);

	vq_pages = alloc_pages(total_pages, PAGE_ALLOC_CONTIGUOUS);
	if(!vq_pages)
		return false;
	
	unsigned long vq_pages_phys = reinterpret_cast<unsigned long>(page_to_phys(vq_pages));

	auto _descs = vq_pages_phys;
	auto _avail = vq_pages_phys + descriptor_table_length;
	auto _used = vq_pages_phys + descriptor_table_length + avail_ring_length;
	
	device->write_config<uint16_t>(pci_common_cfg::queue_select, nr);
	device->write_config<uint16_t>(pci_common_cfg::queue_size, queue_size);
	device->write_config<uint32_t>(pci_common_cfg::queue_desc_low, static_cast<uint32_t>(_descs));
	device->write_config<uint32_t>(pci_common_cfg::queue_desc_high, static_cast<uint32_t>(_descs << 32));
	device->write_config<uint32_t>(pci_common_cfg::queue_device_high, static_cast<uint32_t>(_used << 32));
	device->write_config<uint32_t>(pci_common_cfg::queue_device_low, static_cast<uint32_t>(_used));
	device->write_config<uint32_t>(pci_common_cfg::queue_driver_high, static_cast<uint32_t>(_avail << 32));
	device->write_config<uint32_t>(pci_common_cfg::queue_driver_low, static_cast<uint32_t>(_avail));

	auto& notify = device->notify_cfg();
	auto multiplier = notify.notify_off_mult;

	eff_queue_notify_off = (multiplier * device->read_config<uint16_t>(pci_common_cfg::queue_notify_off));

	device->write_config<uint16_t>(pci_common_cfg::queue_enable, 1);

	descs = reinterpret_cast<virtq_desc*>(PHYS_TO_VIRT(_descs));
	avail = reinterpret_cast<virtq_avail*>(PHYS_TO_VIRT(_avail));
	used = reinterpret_cast<virtq_used*>(PHYS_TO_VIRT(_used));

	return true;
}

bool virtq::has_available_descriptors(size_t nr) const
{
	return avail_descs >= nr;
}

void virtq::allocate_descriptors(virtio_allocation_info &info, bool irq_context)
{
	// Ergh, using spin_lock_irqrestore here is tough since we need to coordinate with wait_for_event_locked 
	auto flags = irq_save_and_disable();
	spin_lock(&desc_alloc_lock);

	auto nr_descs = info.nr_vecs;

	if(!irq_context)
	{
		wait_for_event_locked(&desc_alloc_wq, has_available_descriptors(nr_descs), &desc_alloc_lock);
	}
	else
	{
		while(!has_available_descriptors(nr_descs))
			cpu_relax();
	}

	allocate_buffer_list(info);

	spin_unlock(&desc_alloc_lock);

	irq_restore(flags);
}

unsigned int virtq::alloc_descriptor_internal()
{
	unsigned long desc;
	assert(desc_bitmap.FindFreeBit(&desc) == true);
	avail_descs--;

	return (unsigned int) desc;
}

void virtq_split::allocate_buffer_list(virtio_allocation_info &info)
{
	MUST_HOLD_LOCK(&desc_alloc_lock);
	uint16_t desc_head = 0;
	uint16_t seq = 0;
	uint16_t index = alloc_descriptor_internal();
	auto vec = info.vec;

	for(size_t i = 0; i < info.nr_vecs; i++, vec++)
	{
		if(seq++ == 0)
		{
			desc_head = index;
		}

		virtio_desc_info dinfo;

		if(info.fill_function)
		{
			dinfo = info.fill_function(i, info);
		}
		else
		{
			dinfo.v = *vec;
			dinfo.flags = info.alloc_flags;
		}

		auto v = &dinfo.v;

		virtq_desc *desc = descs + index;

		desc->paddr = (unsigned long) page_to_phys(v->page) + v->page_off;
		desc->length = v->length;

		if(seq - 1 == 0) completions[index] = info.completion;

		bool has_next_desc = i + 1 != info.nr_vecs;
	
		desc->flags = (has_next_desc ? VIRTQ_DESC_F_NEXT : 0) |
		              (dinfo.flags & VIRTIO_ALLOCATION_FLAG_WRITE ? VIRTQ_DESC_F_WRITE : 0);

		if(has_next_desc)
		{
			index = alloc_descriptor_internal();
			desc->next = index;
		}
		else
		{
			desc->next = 0;
		}
	}

	info.first_desc = desc_head;
	if(info.completion) info.completion->descs_pending = info.nr_vecs;
}

void virtq_split::put_buffer(const virtio_allocation_info &info, bool should_notify)
{
	write_memory_barrier();

	avail->ring[avail->idx % this->queue_size] = info.first_desc;
	avail->idx++;

	write_memory_barrier();
	
	if(should_notify) [[likely]]
		notify();
}

void virtq::resubmit_buffer(uint32_t desc, bool should_notify)
{
	virtio_allocation_info info;
	info.first_desc = desc;

	put_buffer(info, should_notify);
}

void virtq_split::notify()
{
	device->notify_cfg().write<uint32_t>(eff_queue_notify_off, nr);
}

cul::pair<unsigned long, size_t> virtq_split::get_buf_from_id(uint16_t id) const
{
	return {descs[id].paddr, descs[id].length};
}

void virtq_split::free_chain(uint32_t id)
{
	size_t processed = 0;
	while(true)
	{
		processed++;
		auto desc = get_desc(id);

		desc_bitmap.FreeBit(id);
		avail_descs++;

		if(!(desc->flags & VIRTQ_DESC_F_NEXT))
			break;
		
		id = desc->next;
	}

	if(processed == 1)
		wait_queue_wake(&desc_alloc_wq);
	else
		wait_queue_wake_all(&desc_alloc_wq);
}

void virtq_split::handle_irq()
{
	while(used->idx != last_seen_used_idx)
	{
		auto &elem = used->ring[last_seen_used_idx % this->queue_size];

		device->handle_used_buffer(elem, this);
		{	
			scoped_lock<spinlock, true> g{desc_alloc_lock};
			reset_completion(elem.id);
			free_chain(elem.id);
		}

		last_seen_used_idx++;
	}
}

void virtq_split::disable_interrupts()
{
	avail->flags |= VIRTQ_AVAIL_F_NO_INTERRUPT;
}

void virtq_split::enable_interrupts()
{
	avail->flags &= ~VIRTQ_AVAIL_F_NO_INTERRUPT;
}

void vdev::handle_vq_irq()
{
	for(auto &c : virtqueue_list)
	{
		if(driver_handle_vq_irq(c->get_nr()) == handle_vq_irq_result::HANDLE)
			c->handle_irq();
	}
}

static bool our_irq(uint32_t status)
{
	/* Automatically tests bit 0 and 1 */
	return status != 0;
}

irqstatus_t vdev::handle_irq()
{
	/* TODO: Handle MSI-X interrupts */

	/* The spec states that reading this automatically clears
	 * the isr status register and de-asserts the interrupt.
	 */

	auto status = isr_cfg().read<uint32_t>(isr_cfg::isr_status);

	if(!our_irq(status))
		return IRQ_UNHANDLED;

	if(status & VIRTIO_ISR_CFG_QUEUE_INTERRUPT)
		handle_vq_irq();
	
	/* TODO: Handle cfg interrupts */

	return IRQ_HANDLED;
}

}

struct pci::pci_id virtio_pci_ids[] = 
{
	{ PCI_ID_DEVICE(VIRTIO_VENDOR_ID, PCI_ANY_ID, NULL) },
	{ PCI_ID_DEVICE(VIRTIO_VENDOR_ID2, PCI_ANY_ID, NULL) },
	{}
};

irqstatus_t virtio_handle_irq(struct irq_context *context, void *cookie)
{
	virtio::vdev *vdv = static_cast<virtio::vdev *>(cookie);

	return vdv->handle_irq();
}

int virtio_probe(struct device *_dev)
{
	pci::pci_device *device = (pci::pci_device *) _dev;
	unique_ptr<virtio::vdev> virtio_device;

	if(device->did() < virtio::pci_device_id_base_transitional ||
	   device->did() > virtio::pci_device_id_max)
	{
		/* Not a virtio device */
		return -1;
	}

	auto addr = device->addr();

	MPRINTF("Found virtio device at %04x:%02x:%02x:%02x\n",
		addr.segment, addr.bus, addr.device,
		addr.function);

	MPRINTF("Device ID %04x\n", device->did());

	auto device_subsystem = virtio::get_virtio_devid(device->did());

	switch(device_subsystem)
	{
#ifdef CONFIG_VIRTIO_NET
		case virtio::network_pci_subsys:
			virtio_device = virtio::create_network_device(device);
			break;
#endif
#ifdef CONFIG_VIRTIO_GPU
		case virtio::gpu_pci_subsys:
			virtio_device = virtio::create_gpu_device(device);
			break;
#endif
#ifdef CONFIG_VIRTIO_BLK
		case virtio::block_pci_subsys:
			virtio_device = virtio::create_blk_device(device);
			break;
#endif
		default:
			return -1;
	}

	assert(install_irq(device->get_intn(), virtio_handle_irq, _dev, IRQ_FLAG_REGULAR,
           virtio_device.get_data()) == 0);

	virtio_device->perform_base_virtio_initialization();
	virtio_device->perform_subsystem_initialization();

	virtio_device.release();

	return 0;
}

struct driver virtio_driver = 
{
	.name = "virtio",
	.devids = &virtio_pci_ids,
	.probe = virtio_probe,
	.bus_type_node = {&virtio_driver}
};

extern "C"
int virtio_init(void)
{
	pci::register_driver(&virtio_driver);
	return 0;
}

MODULE_INIT(virtio_init);
MODULE_INSERT_VERSION();
MODULE_LICENSE(MODULE_LICENSE_MIT);
MODULE_AUTHOR("Pedro Falcato");
