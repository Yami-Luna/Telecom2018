#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/ipaddress.hh>
#include <click/handler.hh>
#include <click/handlercall.hh>
#include <clicknet/ip.h>
#include <clicknet/icmp.h>
#include <clicknet/udp.h>
#include <arpa/inet.h>
#include <string.h>
#include "RegRequest.hh"
#include "RegReply.hh"

CLICK_DECLS

int ipInIpCounter = 0;

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

Packet *ipInIpEncap(Packet *packetToBeEncapsulated, struct in_addr decapsulator, IPAddress publicAddress)
{
	if (!packetToBeEncapsulated->has_network_header()) return 0;

	int offset = 0;
	int tailroom = 0;
	int headroom = sizeof(click_ip);
	int packetsize = headroom + (int) (packetToBeEncapsulated->length());
	WritablePacket * packet = Packet::make(headroom, 0, packetsize, tailroom);

	if (packet == 0) {
		click_chatter( "Cannot make packet");

		return 0;
	}

	memset(packet->data(), 0, packetsize);

	click_ip * innerIP = (click_ip *) (packetToBeEncapsulated->data() + offset);
	click_ip * ip = initIPHeader(packet, (click_ip *) (packet->data() + offset), packetsize, 4, ipInIpCounter++, 128, publicAddress, decapsulator);
	offset += sizeof(click_ip);
	packet->set_network_header((unsigned char *) ip, sizeof(click_ip));

	memcpy(packet->data() + offset, packetToBeEncapsulated->data(), packetToBeEncapsulated->length());

	return packet;
}

RegReply::RegReply() : timer(this), isHomeAgent(false), isMobileNode(false), _rr(0), _identification(0) {};


int RegReply::configure(Vector<String> &conf, ErrorHandler *errh)
{
	if (cp_va_kparse(conf, this, errh,	"ISHOMEAGENT", cpkN, cpBool, &isHomeAgent,
										"ISMOBILENODE", cpkN, cpBool, &isMobileNode,
										"ME", cpkM, cpIPAddress, &_me,
										"LIFETIME", cpkM, cpInteger, &_lifetime,
										"REQUESTER", cpkN, cpElement, &_rr,
										"PUBLIC", cpkN, cpIPAddress, &_public,
										cpEnd) < 0) return -1;

	if (isHomeAgent)
	{
		timer.initialize(this);
		timer.schedule_after_msec(1000);
	}

	return 0;
}

void RegReply::run_timer(Timer * timer)
{
	timer->schedule_after_msec(1000);
	list<MobilityBinding>::iterator iter = mobilityBindings.begin();
	while (iter != mobilityBindings.end())
	{
		--(iter->lifetimeRemaining);

		if (iter->lifetimeRemaining == 0)
		{
			click_chatter("Home Agent -- Registration lifetime ran out for mobile node.");

			list<MobilityBinding>::iterator toRemove = iter;
			++iter;
			mobilityBindings.erase(toRemove);
		}
		else
			++iter;
	}
}

void RegReply::generateReply(Packet * p)
{
	click_udp * oldudp = (click_udp *) (p->data() + sizeof(click_ip));

	int offset = 0;
	int tailroom = 0;
	int headroom = sizeof(click_ip);
	int packetsize = headroom + sizeof(click_udp) + sizeof(RegReplyData);
	WritablePacket * packet = Packet::make(headroom, 0, packetsize, tailroom);

	if (packet == 0) {
		click_chatter( "Cannot make packet");

		return;
	}

	memset(packet->data(), 0, packetsize);

	click_ip * ip = initIPHeader(packet, (click_ip *) (packet->data() + offset), packetsize, 17, 1, 128, p->ip_header()->ip_dst, p->ip_header()->ip_src);
	offset += sizeof(click_ip);

	click_udp * udp = (click_udp *) (packet->data() + offset);
	udp->uh_sport = oldudp->uh_dport;
	udp->uh_dport = oldudp->uh_sport;
	udp->uh_ulen = htons(sizeof(click_udp) + sizeof(RegReplyData));
	offset += sizeof(click_udp);
	packet->set_network_header((unsigned char *) ip, sizeof(click_ip));

	RegRequestData * rreq = (RegRequestData *) (p->data() + sizeof(click_ip) + sizeof(click_udp));

	RegReplyData * rr = (RegReplyData *) (packet->data() + offset);
	rr->type = 3;

	int oldsum = oldudp->uh_sum;
	oldudp->uh_sum = 0;
	if ((oldsum != 0) && (oldsum != click_in_cksum((const unsigned char *) oldudp, sizeof(click_udp) + sizeof(RegRequestData)))) {
		return;
	} else if ((rreq->flags & (0x1 << 1)) || (rreq->flags & 0x1)) {
		click_chatter("Home Agent -- Sending error 134, reserved flags were incorrectly set.");
		rr->code = htons(134);
	} else if ((rreq->flags >> 7) & 0x1) { 
		click_chatter("Home Agent -- Sending error 1, simultaneous bindings are unsupported.");
		rr->code = htons(1); // simultaneous bindings unsupported
	} else if (false) {
		click_chatter("Home Agent -- Sending error 128, no reason specified.");
		rr->code = htons(128); // reason unspecified
		// rr->code = 135; // too many simultaneous bindings not possible if you don't support simultaneous bindings
	} else {
		rr->code = htons(0); // registration accepted
	}

	// See if the IP addresses are in the same network, then we don't need to add the mobile node.
	bool isAtHome = IPAddress(p->ip_header()->ip_src).matches_prefix(_me, IPAddress::make_prefix(24));

	if (ntohs(rreq->lifetime) > _lifetime)
		rr->lifetime = htons(_lifetime);
	else
		rr->lifetime = rreq->lifetime;
	rr->homeAddress = rreq->homeAddress;

	if (isAtHome)
		rr->homeAgent = _me;
	else
		rr->homeAgent = rreq->homeAgent;
	rr->identification = ntohs(rreq->identification);
	udp->uh_sum = 0;
	udp->uh_sum = click_in_cksum((const unsigned char *) udp, sizeof(click_udp) + sizeof(RegReplyData));

	list<MobilityBinding>::iterator iter = mobilityBindings.begin();

	while (iter != mobilityBindings.end())
	{
		if (IPAddress(iter->mobileNode).hashcode() == IPAddress(rr->homeAddress).hashcode())
		{
			mobilityBindings.erase(iter);
			break;
		}

		++iter;
	}

	if (rr->code == 0)
	{
		if (!isAtHome) {
			MobilityBinding mob;
			mob.mobileNode = rr->homeAddress;
			mob.careOfAddress = rreq->careOfAddress;
			mob.lifetimeRemaining = ntohs(rr->lifetime);
			mob.identification = ntohs(rr->identification);
			mobilityBindings.push_back(mob);

			if (iter == mobilityBindings.end())
				click_chatter("Home Agent -- Mobile node registrated.");
			else
				click_chatter("Home Agent -- Mobile node re-registrated.");
		}
		else
			click_chatter("Home Agent -- Mobile node deregistrated.");
	}

	output(0).push(packet);
}

void RegReply::push(int port, Packet *p)
{
	generateReply(p);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RegReply)

