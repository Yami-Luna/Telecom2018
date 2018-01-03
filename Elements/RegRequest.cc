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
#include "RegRequest.hh"
#include "RegReply.hh"

CLICK_DECLS

click_ip * initIPHeader(WritablePacket * packet, click_ip * ip, int packetsize, int proto, int id, int ttl, IPAddress src, IPAddress dst)
{
	ip->ip_v = 4;
	ip->ip_hl = 5;
	ip->ip_tos = 0;
	ip->ip_len = htons(packetsize);
	ip->ip_id = htons(id);
	ip->ip_off = 0;
	ip->ip_ttl = ttl;
	ip->ip_p = proto;
	ip->ip_src = src;
	ip->ip_dst = dst;
	packet->set_dst_ip_anno(ip->ip_dst);
	ip->ip_sum = 0;
	ip->ip_sum = click_in_cksum((const unsigned char *) ip, sizeof(click_ip));

	return ip;
}

void doRegister(Timer * timer, void * data)
{
	((RegRequest *) data)->reRegister();
}

RegRequest::RegRequest() : counter(0), _currentAgent(0), timer(this), _lastP(0), _rr(0), _registrated(false), reregister(doRegister, (void *) this), _lastRequest(0), _sol(0), _lastSequenceNumber(-1) {}

RegRequest::~RegRequest() {}

int RegRequest::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh,	"ISMOBILENODE", cpkM, cpBool, &isMobileNode,
										"GATEWAY", cpkM, cpIPAddress, &_gateway,
										"ME", cpkM, cpIPAddress, &_me,
										"SOLICITATION", cpkN, cpElement, &_sol,
										"LIFETIME", cpkM, cpInteger, &_lifetime,
										"REPLIER", cpkN, cpElement, &_rr,
										cpEnd) < 0) return -1;

	if (isMobileNode)
	{
		timer.initialize(this);
		timer.schedule_after_msec(0);

		reregister.initialize(this);
	}

	return 0;
}

void RegRequest::run_timer(Timer* t) {
	timer.schedule_after_msec(900 + 200 * (rand() / RAND_MAX));
	push_packet((Packet*) 0);
}

bool is_bit_set(unsigned value, unsigned bitindex)
{
    return (value & (1 << bitindex)) != 0;
}

void RegRequest::push_packet(Packet * p)
{
	if (time(0) == _lastRequest)
	{
		reregister.clear();
		reregister.schedule_after_msec(1000);

		return;
	}

	click_icmp_echo * icmp_h = (click_icmp_echo *) (p->data() + sizeof(click_ip));
	click_udp * udph = (click_udp *) (p->data() + sizeof(click_ip));
	click_ip *oldip = (click_ip *) p->ip_header();

	bool isHomeAgent = IPAddress(oldip->ip_src).matches_prefix(_me, IPAddress::make_prefix(24));

	if (isHomeAgent)
	{
		click_chatter("Mobile Node -- Sending deregistration to home agent.");

		reregister.clear();
	}
	else
	{
		click_chatter("Mobile Node -- Sending registration to foreign agent.");

		reregister.clear();
		reregister.schedule_after_msec(_lifetime * 1000 - 500);
	}

	MobileAgentAdvertisement * maa = (MobileAgentAdvertisement *) (p->data() + sizeof(click_ip) + sizeof(click_icmp_echo) / 2 + sizeof(ICMPRouterAdvertisement));

	if (!isHomeAgent && !is_bit_set(maa->flags, 7)) {
		click_chatter("Mobile Node -- The foreign agent I'm connected with does not seem to support registration.");
	} else if (p->length() > sizeof(click_ip) + sizeof(click_icmp_echo)) {
		int offset = 0;
		int tailroom = 0;
		int headroom = sizeof(click_ip);
		int packetsize = headroom + sizeof(click_udp) + sizeof(RegRequestData);
		WritablePacket * packet = Packet::make(headroom, 0, packetsize, tailroom);

		if (packet == 0) {
			click_chatter( "Cannot make packet");
			p->kill();
			return;
		}

		ICMPRouterAdvertisement * ira = (ICMPRouterAdvertisement *) (packet->data() + sizeof(click_ip) + sizeof(click_icmp_echo) / 2);
		int lifetime = ira->lifetime;
		// TODO read and delete from list
		if (agents.find(oldip->ip_dst) != agents.end()) {
			agents.insert(std::pair<struct in_addr, int>(oldip->ip_dst, lifetime));
		} else {
			agents.find(oldip->ip_dst)->second = lifetime;
		}

		memset(packet->data(), 0, packetsize);

		click_ip * ip = initIPHeader(packet, (click_ip *) (packet->data() + offset), packetsize, 17, counter, 128, _me, oldip->ip_src);
		offset += sizeof(click_ip);

		click_udp * udp = (click_udp *) (packet->data() + offset);
		udp->uh_sport = htons(1337);
		udp->uh_dport = htons(434);
		udp->uh_ulen = htons(sizeof(click_udp) + sizeof(RegRequestData));
		offset += sizeof(click_udp);
		packet->set_network_header((unsigned char *) ip, sizeof(click_ip) + sizeof(click_udp));

		RegRequestData *rr = (RegRequestData *) (packet->data() + offset);
		rr->type = 1;
		rr->flags = 1 << 6;

		if (isHomeAgent)
			rr->lifetime = 0;
		else
			rr->lifetime = htons(_lifetime);

		rr->homeAddress = oldip->ip_dst;
		rr->homeAgent = _gateway;
		memcpy(&rr->careOfAddress, (IPAddress *) (p->data() + sizeof(click_ip) + sizeof(click_icmp_echo) / 2 + sizeof(ICMPRouterAdvertisement) + sizeof(MobileAgentAdvertisement)), sizeof(IPAddress));
		rr->identification = htons(++counter);

		udp->uh_sum = 0;
		udp->uh_sum = click_in_cksum((const unsigned char *) udp, sizeof(click_udp) + sizeof(RegRequestData));

		output(0).push(packet);

		_lastRequest = time(0);
	}
}

void RegRequest::push(int, Packet *p) {
	push_packet(p);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RegRequest)

