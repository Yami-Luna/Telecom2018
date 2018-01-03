#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/ipaddress.hh>
#include <clicknet/ip.h>
#include <clicknet/icmp.h>
#include "Advertisement.hh"

CLICK_DECLS

Advertisement::Advertisement() : timer(this), ctr(0) { }

Advertisement::~Advertisement() {}

int Advertisement::configure(Vector<String> &conf, ErrorHandler *errh) {
	bool timerEnabled;
	if (cp_va_kparse(conf,this,errh, "SRC", cpkM, cpIPAddress, &_source,
					 "COA", cpkN, cpIPAddress, &_careofaddress,
					 "TIMER", cpkM, cpBool, &timerEnabled,
					 "ISHOME", cpkM, cpBool, &isHomeAgent,
					 "LIFETIME", cpkM, cpInteger, &_lifetime,
					 "REGLIFETIME", cpkM, cpInteger, &_registrationLifetime,
					 cpEnd) < 0) return -1;

	if (timerEnabled)
	{
		timer.initialize(this);
		timer.schedule_after_msec(0);
	}

	return 0;
}

void Advertisement::run_timer(Timer* t) {
	timer.schedule_after_msec(900 + 200 * (rand() / RAND_MAX));
	push_packet(0,true);
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
	click_ip * ipheader = (click_ip *) (packet->data() + offset);
	ipheader->ip_v = 4;
	ipheader->ip_hl = 5;
	ipheader->ip_tos = 0;
	ipheader->ip_len = htons(size);
	ipheader->ip_id = htons(ctr);
	ipheader->ip_off = 0;
	ipheader->ip_ttl = 1;
	ipheader->ip_p = 1;
	ipheader->ip_src = _source;
	if (broadcast) {
		ipheader->ip_dst = IPAddress("255.255.255.255");
	} else {
		ipheader->ip_dst = p->ip_header()->ip_src;
	}
	packet->set_dst_ip_anno(ipheader->ip_dst);
	ipheader->ip_sum = 0;
	ipheader->ip_sum = click_in_cksum((const unsigned char *) ipheader, sizeof(click_ip));

	offset += sizeof(click_ip);
	packet->set_network_header((unsigned char *) ipheader, sizeof(click_ip));

	//initiate icmp header
	click_icmp_echo * icmpheader = (click_icmp_echo *) (packet->data() + offset);
	icmpheader->icmp_type = 9;
	icmpheader->icmp_code = 0;
	icmpheader->icmp_identifier = 0;
	icmpheader->icmp_sequence = htons(ctr);

	//rollover handling
	if (ctr == 0xffff) {
		ctr = 256;
	} else {
		ctr++;
	}
	offset += sizeof(click_icmp_echo) / 2;

	//set ICMP Router Advertisement
	ICMPRouterAdvertisement * icmpra = (ICMPRouterAdvertisement *) (packet->data() + offset);
	icmpra->advertisement_count = 1;
	icmpra->address_entry_size = 2;
	icmpra->lifetime = htons(_lifetime);
	memcpy(&icmpra->router_address, &_source, sizeof(IPAddress));
	icmpra->preference_level = 0x00000001;
	offset += sizeof(ICMPRouterAdvertisement);

	//set Mobile Agent Advertisement
	MobileAgentAdvertisement * maa = (MobileAgentAdvertisement *) (packet->data() + offset);
	maa->type = 16;
	maa->length = 6;
	maa->sequence_number = htons(ctr);
	maa->registration_lifetime = htons(_registrationLifetime);

	if (isHomeAgent) {
		maa->flags = (1 << 13);
		icmpheader->icmp_cksum = 0;
		icmpheader->icmp_cksum = click_in_cksum((const unsigned char *) icmpheader, sizeof(click_icmp_echo) / 2 + sizeof(ICMPRouterAdvertisement) + sizeof(MobileAgentAdvertisement));
	} else {
		maa->length += 4;
		maa->flags = (1 << 12) | (1 << 15);
		offset += sizeof(MobileAgentAdvertisement);
		IPAddress * ipAddress = (IPAddress *) (packet->data() + offset);
		memcpy(ipAddress, &_careofaddress, sizeof(IPAddress));
		icmpheader->icmp_cksum = 0;
		icmpheader->icmp_cksum = click_in_cksum((const unsigned char *) icmpheader, sizeof(click_icmp_echo) / 2 + sizeof(ICMPRouterAdvertisement) + sizeof(MobileAgentAdvertisement) + sizeof(IPAddress));
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
EXPORT_ELEMENT(Advertisement)

