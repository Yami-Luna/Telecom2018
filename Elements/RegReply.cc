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
#include "regRequest.hh"
#include "regReply.hh"

CLICK_DECLS

int ipInIpCounter = 0;

Packet* encapsulate(Packet* packet, struct in_addr decapsulator, IPAddress publicAddress)
{
	if (!packet->has_network_header()) return 0;

	int offset = 0;
	int tailroom = 0;
	int headroom = sizeof(click_ip);
	int size = headroom + (int) (packet->length());
	WritablePacket * returnPacket = Packet::make(headroom, 0, size, tailroom);

	if (returnPacket == 0) {
		click_chatter("Failed to make packet");

		return 0;
	}

	memset(returnPacket->data(), 0, size);

	// Never used?
	click_ip* innerIP = (click_ip *) (packet->data() + offset);

	// IP Header
	click_ip* ipheader = (click_ip *) (returnPacket->data() + offset);

	ipheader->ip_v = 4;
	ipheader->ip_hl = 5;
	ipheader->ip_tos = 0;
	ipheader->ip_len = htons(size);
	ipheader->ip_id = htons(ipInIpCounter);
	ipInIpCounter++;
	ipheader->ip_off = 0;
	ipheader->ip_ttl = 128;
	ipheader->ip_p = 4;
	ipheader->ip_src = publicAddress;
	ipheader->ip_dst = decapsulator;
	packet->set_dst_ip_anno(ipheader->ip_dst);
	ipheader->ip_sum = 0;
	ipheader->ip_sum = click_in_cksum((const unsigned char *) ipheader, sizeof(click_ip));

	offset += sizeof(click_ip);
	returnPacket->set_network_header((unsigned char *) ip, sizeof(click_ip));

	memcpy(returnPacket->data() + offset, packet->data(), packet->length());

	return returnPacket;
}

RegistrationReply::RegistrationReply() : timer(this), isHomeAgent(false), isMobileNode(false), _rr(0), _identification(0) {};


int RegistrationReply::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh,\
					"ISHOMEAGENT", cpkN, cpBool, &isHome,
					"ISMOBILENODE", cpkN, cpBool, &isMobile,
					"ME", cpkM, cpIPAddress, &selfIP,
					"LIFETIME", cpkM, cpInteger, &lifetime,
					"REQUESTER", cpkN, cpElement, &regRequest,
					"PUBLIC", cpkN, cpIPAddress, &publicIP,
					cpEnd) < 0) return -1;

	if (isHome) {
		timer.initialize(this);
		timer.schedule_after_msec(1000);
	}

	return 0;
}

// Not needed yet afaik?
void RegistrationReply::run_timer(Timer * timer)
{
	timer->schedule_after_msec(1000);
	list<MobilityBinding>::iterator iter = mobilityBindings.begin();
	while (iter != mobilityBindings.end())
	{
		--(iter->lifetimeRemaining);

		if (iter->lifetimeRemaining == 0)
		{
			click_chatter("HA --- Registration lifetime over.");

			list<MobilityBinding>::iterator toRemove = iter;
			++iter;
			mobilityBindings.erase(toRemove);
		}
		else
			++iter;
	}
}

void RegistrationReply::forward(Packet * p)
{
	click_udp * oldudp = (click_udp *) (p->data() + sizeof(click_ip));

	click_chatter("FA --- Forwarding RegReply.");
	RegReplyData * oldrr = (RegistrationReplyData *) (p->data() + sizeof(click_ip) + sizeof(click_udp));

	int offset = 0;
	int tailroom = 0;
	int headroom = sizeof(click_ip);
	int size = headroom + sizeof(click_udp) + sizeof(ReqRequestData);
	WritablePacket * packet = Packet::make(headroom, 0, size, tailroom);

	if (packet == 0) {
		click_chatter("Failed to create packet.");
		return;
	}

	memcpy(packet->data(), p->data(), size);

	click_ip* ipheader = (click_ip *) (packet->data() + offset);

	ipheader->ip_v = 4;
	ipheader->ip_hl = 5;
	ipheader->ip_tos = 0;
	ipheader->ip_len = htons(size);
	ipheader->ip_id = htons(1);
	ipheader->ip_off = 0;
	ipheader->ip_ttl = 128;
	ipheader->ip_p = 17;
	ipheader->ip_src = p->ip_header()->ip_src;
	ipheader->ip_dst = oldrr->homeAddress;
	packet->set_dst_ip_anno(ipheader->ip_dst);
	ipheader->ip_sum = 0;
	ipheader->ip_sum = click_in_cksum((const unsigned char *) ipheader, sizeof(click_ip));
	packet->set_dst_ip_anno(ipheader>ip_dst);
	offset += sizeof(click_ip);

	click_udp * udp = (click_udp *) (packet->data() + offset);
	offset += sizeof(click_udp);
	packet->set_network_header((unsigned char *) ipheader, sizeof(click_ip));

	RegistrationReplyData * rr = (RegReplyData *) (packet->data() + offset);

	if (ntohs(rr->lifetime) > lifetime)
		rr->lifetime = htons(lifetime);

	int oldsum = oldudp->uh_sum;
	oldudp->uh_sum = 0;
	if ((oldsum != 0) && (oldsum != click_in_cksum((const unsigned char *) oldudp, sizeof(click_udp) + sizeof(RegReplyData)))) {
		return;
	} else if (oldrr->id != id) {
		return;
	} else if (oldrr->lifetime == 0) {
		 // When is a registration reply poorly formed? There are no reserved bits (unlike the request).
		click_chatter("FA -- Error 71");
		rr->code = 71;
	} else if (false) {
		rr->code = 64; // reason unspecified
	}
	udp->uh_sum = 0;
	udp->uh_sum = click_in_cksum((const unsigned char *) udp, sizeof(click_udp) + sizeof(RegReplyData));

	output(0).push(packet);
}

void RegistrationReply::generateReply(Packet * p)
{
	click_udp * oldudp = (click_udp *) (p->data() + sizeof(click_ip));

	int offset = 0;
	int tailroom = 0;
	int headroom = sizeof(click_ip);
	int size = headroom + sizeof(click_udp) + sizeof(RegistrationReplyData);
	WritablePacket * packet = Packet::make(headroom, 0, size, tailroom);

	if (packet == 0) {
		click_chatter("Failed to create packet.");

		return;
	}

	memset(packet->data(), 0, size);

	click_ip* ipheader = (click_ip *) (packet->data() + offset);
	ipheader->ip_v = 4;
	ipheader->ip_hl = 5;
	ipheader->ip_tos = 0;
	ipheader->ip_len = htons(size);
	ipheader->ip_id = htons(1);
	ipheader->ip_off = 0;
	ipheader->ip_ttl = 128;
	ipheader->ip_p = 17;
	ipheader->ip_src = p->ip_header()->ip_dst;
	ipheader->ip_dst = p->ip_header()->ip_src;
	packet->set_dst_ip_anno(ipheader->ip_dst);
	ipheader->ip_sum = 0;
	ipheader->ip_sum = click_in_cksum((const unsigned char *) ipheader, sizeof(click_ip));

	offset += sizeof(click_ip);

	click_udp * udp = (click_udp *) (packet->data() + offset);
	udp->uh_sport = oldudp->uh_dport;
	udp->uh_dport = oldudp->uh_sport;
	udp->uh_ulen = htons(sizeof(click_udp) + sizeof(RegReplyData));
	offset += sizeof(click_udp);
	packet->set_network_header((unsigned char *) ipheader, sizeof(click_ip));

	RegRequestData * rreq = (RegRequestData *) (p->data() + sizeof(click_ip) + sizeof(click_udp));

	RegReplyData * rr = (RegReplyData *) (packet->data() + offset);
	rr->type = 3;

	int oldsum = oldudp->uh_sum;
	oldudp->uh_sum = 0;
	if ((oldsum != 0) && (oldsum != click_in_cksum((const unsigned char *) oldudp, sizeof(click_udp) + sizeof(RegRequestData)))) {
		return;
	} else if ((rreq->flags & (0x1 << 1)) || (rreq->flags & 0x1)) {
		click_chatter("HA --- Error 134");
		rr->code = htons(134);
	} else if ((rreq->flags >> 7) & 0x1) { 
		click_chatter("HA --- Error 1");
		rr->code = htons(1); // simultaneous bindings unsupported
	} else if (false) {
		click_chatter("HA --- Error 128");
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
	rr->id = ntohs(rreq->id);
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
				click_chatter("HA --- Mobile node registrated.");
			else
				click_chatter("HA --- Mobile node re-registrated.");
		}
		else
			click_chatter("HA --- Mobile node deregistrated.");
	}

	output(0).push(packet);
}

void RegistrationReply::keepId(int newId)
{
	id = newId;
}

int doKeepId(const String & data, Element * element, void * user_data, ErrorHandler * error)
{
	((RegistrationReply *) element)->keepId(ntohs(atoi(data.c_str())));
}

void RegistrationReply::add_handlers()
{
	int data = 0;
	add_write_handler("keepId", doKeepId, data, 0);
}

void RegistrationReply::push(int port, Packet *p)
{
	if (isMobile)
	{
		RegReplyData* rr = (RegReplyData *) (p->data() + sizeof(click_ip) + sizeof(click_udp));

		HandlerCall::call_write("lifetime", String(ntohs(rr->lifetime)), (Element *) reqRequest, new ErrorHandler());
	}
	else
	{
		if (port == 1) {
			list<MobilityBinding>::iterator iter = mobilityBindings.begin();

			while (iter != mobilityBindings.end())
			{
				if (IPAddress(iter->mobileNode).hashcode() == IPAddress(p->ip_header()->ip_dst).hashcode())
					break;

				++iter;
			}
			if (iter != mobilityBindings.end()) {
				Packet * packet = ipInIpEncap(p, iter->careOfAddress, publicIP);

				if (packet) {
					output(1).push(packet);
					p->kill();
					return;
				}
			}
			output(2).push(p);
			return;
		}

		if (isHome)
			generateReply(p);
		else
			forward(p);
	}

	p->kill();
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RegReply)
