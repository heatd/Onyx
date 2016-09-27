/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/

#include <stdlib.h>
#include <string.h>

#include <kernel/ethernet.h>

#include <drivers/pci.h>
#include <drivers/e1000.h>

char mac_address[6] = {0};
int ethernet_init()
{
	PCIDevice *dev = get_pcidev_from_classes(CLASS_NETWORK_CONTROLLER, 0, 0);
	if(!dev)
		return 1;
	
	if(dev->vendorID == INTEL_VEND && dev->deviceID == E1000_DEV)
		return e1000_init();
	if(dev->vendorID == INTEL_VEND && dev->deviceID == E1000_I217)
		return e1000_init();
	if(dev->vendorID == INTEL_VEND && dev->deviceID == E1000_82577LM)
		return e1000_init();
	else
		return 1;
}
uint8_t *packet = NULL;
uint16_t packet_len = 0;
void eth_set_packet_buf(uint8_t *buf)
{
	packet = buf;
}
void eth_set_packet_len(uint16_t len)
{
	packet_len = len;
}
static device_send_packet dev_send_packet;
void eth_set_dev_send_packet(device_send_packet p)
{
	dev_send_packet = p;
}
int eth_send_packet(char *destmac, char *payload, uint16_t len, uint16_t protocol)
{
	ethernet_header_t *hdr = malloc(len + sizeof(ethernet_header_t) + sizeof(ethernet_footer_t));
	if(!hdr)
		return 1;
	memset(hdr, 0, sizeof(ethernet_header_t));
	memcpy(&hdr->payload, payload, len);
	hdr->ethertype = LITTLE_TO_BIG16(protocol);
	memcpy(&hdr->mac_dest, destmac, 6);
	memcpy(&hdr->mac_source, &mac_address, 6);
	printf("eth: mac_dest: %x:%x:%x:%x:%x:%x\n    mac_source: %x:%x:%x:%x:%x:%x\n    ethertype: %x\n", hdr->mac_dest[0], hdr->mac_dest[1], hdr->mac_dest[2], hdr->mac_dest[3], hdr->mac_dest[4], hdr->mac_dest[5],
	hdr->mac_dest[0], hdr->mac_dest[1], hdr->mac_dest[2], hdr->mac_dest[3], hdr->mac_dest[4], hdr->mac_dest[5], hdr->ethertype);
	dev_send_packet(hdr, len + sizeof(ethernet_header_t) + sizeof(ethernet_footer_t));
	free(hdr);
	return 0;
}