#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/handler.hh>
#include <click/handlercall.hh>
#include <click/ipaddress.hh>
#include <clicknet/ip.h>
#include <clicknet/icmp.h>
#include <clicknet/udp.h>
#include <arpa/inet.h>
#include <string.h>
#include "Advertisement.hh"
#include "MNRegRequest.hh"
#include "MNRegReply.hh"

CLICK_DECLS

void MNRegRequest::push(int, Packet *p) {
	// Create the request packet
	int tailroom = 0;
	int headroom = sizeof(click_ip);
	int packetsize = headroom + sizeof(click_udp) + sizeof(MNRegRequestData);
	WritablePacket * packet = Packet::make(headroom, 0, packetsize, tailroom);
	if (packet == 0) return click_chatter("MNRegRequest.push: cannot make packet!");

	// Zero out
	memset(packet->data(), 0, packet->length());

	// IP Header
	click_ip* ipheader = (click_ip*)(packet->data());
	ipheader->ip_v = 4;
	ipheader->ip_hl = 5;
	ipheader->ip_tos = 0;
	ipheader->ip_len = htons(packetsize);
	ipheader->ip_id = 0; // Should be a counter
	ipheader->ip_off = 0;
	ipheader->ip_ttl = 1;
	ipheader->ip_p = 1;
	ipheader->ip_src = // ?
	ipheader->ip_dst = // ?

	// IP Checksum

	// UDP Header

	// MNRegRequestData

	MNRegRequestData* rrdata = (MNRegRequest*) packet->data();
	rrdata->type = 1;
	rrdata->flags = 1 << 6;
	rrdata->lifetime = // ?
	rrdata->homeAddress = // ?
	rrdata->homeAgent = // ?
	rrdata->careOfAddress = // ?
	rrdata->identification = // ?
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RegRequest)
