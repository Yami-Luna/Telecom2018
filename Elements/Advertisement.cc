#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/ipaddress.hh>
#include <clicknet/ip.h>
#include <clicknet/icmp.h>
#include "Advertisement.hh"
#include "IPHeader.hh"

CLICK_DECLS

Advertisement::Advertisement() : counter(0) { }

Advertisement::~Advertisement() {}

int Advertisement::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf,this,errh, "SRC", cpkM, cpIPAddress, &_srcIP,
					 "COA", cpkN, cpIPAddress, &_coaIP,
					 "ISHOME", cpkM, cpBool, &isHomeAgent,
					 "LIFETIME", cpkM, cpInteger, &_lifetime,
					 "REGLIFETIME", cpkM, cpInteger, &_regLifetime,
					 cpEnd) < 0) return -1;

	return 0;
}

void Advertisement::push_packet(Packet *p, bool broadcast = false) {
	//print who's sending the advertisement
	if (isHomeAgent) {
		click_chatter("HA --- Sending advertisement.");
	} else {
		click_chatter("FA --- Sending advertisement.");
	}

	//create new packet
	int offset = 0;
	int tailroom = 0;
	int headroom = sizeof(click_ip);
	int size = headroom + sizeof(click_icmp_echo) / 2 + sizeof(ICMPRouterAdvertisement) + sizeof(MobileAgentAdvertisement);
	WritablePacket * packet = Packet::make(headroom,0,size,tailroom);
	
	if (packet == 0) {
		click_chatter("Failed to make packet.");
		p->kill();
		return;
	}

	//set data to 0
	memset(packet->data(),0,size);

	//initiate ip header
	click_ip * ip;
	if (broadcast) {
		ip = initIPHeader(packet, (click_ip *) (packet->data() + offset), size, 1, counter, 1, _srcIP, IPAddress("255.255.255.255"));
	} else {
		ip = initIPHeader(packet, (click_ip *) (packet->data() + offset), size, 1, counter, 1, _srcIP, p->ip_header()->ip_src);
	}

	offset += sizeof(click_ip);
	packet->set_network_header((unsigned char *) ip, sizeof(click_ip));

	//initiate icmp header
	click_icmp_echo * icmp = (click_icmp_echo *) (packet->data() + offset);

	icmp->icmp_type = 9;
	icmp->icmp_code = 0;
	icmp_icmp_identifier = 0;
	icmp->icmp_sequence = htons(counter);

	//rollover handling
	if (counter == 0xffff) {
		counter = 256;
	} else {
		counter++;
	}
	offset += sizeof(click_icmp_echo) / 2;

	//set ICMP Router Advertisement
	ICMPRouterAdvertisement * ira = (ICMPRouterAdvertisement *) (packet->data() + offset);
	ira->num_addr = 1;
	ira->address_entry_size = 2;
	ira->lifetime = htons(_lifetime);
	memcpy(&ira->router_address, &_srcIP, sizeof(IPAddress));
	ira->preference = 0x00000001;
	offset += sizeof(ICMPRouterAdvertisement);

	//set Mobile Agent Advertisement
	MobileAgentAdvertisment * maa = (MobileAgentAdvertisement *) (packet->data() + offset);
	mma->type = 16
	mma->length = 6;
	mma->seq_nr = htons(counter);
	mma->lifetime = htons(_reqLifetime);

	if (isHomeAgent) {
		mma->flags = (1 << 13)
		icmp->icmp_cksum = 0;
		icmp->icmp_cksum = click_in_cksum((const unsigned char *) icmp, sizeof(click_icmp_echo) / 2 + sizeof(ICMPRouterAdvertisement) + sizeof(MobileAgentAdvertisement));
	} else {
		mma->length += 4;
		mma->flags = (1 << 12) | (1 << 15);
		offset += sizeof(MobileAgentAdvertisement);
		IPAddress * ipAddress = (IPAddress *) (packet->data() + offset);
		memcpy(ipAddress, &_coaIP, sizeof(IPAddress));
		icmp->icmp_cksum = 0;
		icmp->icmp_cksum = click_in_cksum((const unsigned char *) icmp, sizeof(click_icmp_echo) / 2 + sizeof(ICMPRouterAdvertisement) + sizeof(MobileAgentAdvertisement)) + sizeof(IPAddress));
	}

	//push the packet
	output(0).push(packet);

	if (!broadcast) {
		p->kill();
	}
}

void Advertisement::push(int, Packet *p) {
	push_packet(p);
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(IPHeader)
EXPORT_ELEMENT(Advertisement)
