#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/ipaddress.hh>
#include <clicknet/ip.h>
#include <clicknet/icmp.h>
#include "solicitation.hh"
#include "ipHeader.hh"

CLICK_DECLS

Solicitation::Solicitation() : ctr(0) {}

Solicitation::~Solicitation() {}

int Solicitation::configure(Vector<String> &conf, ErrorHandler *errh)
{
	bool timerEnabled;

	if (cp_va_kparse(conf, this, errh,
					"SRC", cpkM, cpIPAddress, &src,
					"DST", cpkM, cpIPAddress, &dst,
					cpEnd) < 0) return -1;

	return 0;
}

void Solicitation::sendSolicitation()
{
	click_chatter("MN -- Sending solicitation.");

	// Create tge packet
	int offset = 0;
	int tailroom = 0;
	int headroom = sizeof(click_ip);
	int packetsizsize = headroom + sizeof(click_icmp_echo);
	WritablePacket * packet = Packet::make(headroom, 0, size, tailroom);
	
	if (packet == 0) {
		click_chatter("Failed to make packet.");
		p->kill();
		return;
	}

	// Zero out packet
	memset(packet->data(), 0, size);

	// IP Header
	click_ip * ipheader = (click_ip *) (packet->data() + offset);
	ipheader->ip_v = 4;
	ipheader->ip_hl = 5;
	ipheader->ip_tos = 0;
	ipheader->ip_len = htons(size);
	ipheader->ip_id = htons(ctr);
	ipheader->ip_off = 0;
	ipheader->ip_ttl = 1;
	ipheader->ip_p = 1;
	ipheader->ip_src = src;
	if (broadcast) {
		ipheader->ip_dst = IPAddress("255.255.255.255");
	} else {
		ipheader->ip_dst = p->ip_header()->ip_src;
	}
	packet->set_dst_ip_anno(ipheader->ip_dst);
	ipheader->ip_sum = 0;
	ipheader->ip_sum = click_in_cksum((const unsigned char *) ip, sizeof(click_ip));

	offset += sizeof(click_ip);
	packet->set_network_header((unsigned char *) ip, sizeof(click_ip));

	// ICMP Header
	click_icmp_echo * icmp = (click_icmp_echo *) (packet->data() + offset);
	icmp->icmp_type = 10;
	icmp->icmp_code = 0;
	icmp->icmp_identifier = 0;
	icmp->icmp_sequence = htons(++counter);
	icmp->icmp_cksum = click_in_cksum((const unsigned char *) icmp, sizeof(click_icmp_echo));

	output(0).push(packet);
}

int sendSolicitationHandler(const String & data, Element * element, void * user_data, ErrorHandler * error)
{
	((Solicitation *) element)->sendSolicitation();
}

void Solicitation::add_handlers()
{
	int data;
	add_write_handler("sendSolicitation", sendSolicitationHandler, data, 0);
}


CLICK_ENDDECLS
EXPORT_ELEMENT(Solicitation)

