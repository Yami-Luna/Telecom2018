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

void doRegister(Timer * timer, void * data)
{
	((RegistrationRequest *)data)->reRegister();
}

RegRequest::RegRequest() : ctr(0), _currentAgent(0), timer(this), _lastP(0), _rr(0), _registrated(false), reregister(doRegister, (void *)this), _lastRequest(0), _sol(0), _lastSequenceNumber(-1) {}

RegRequest::~RegRequest() {}

int RegRequest::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, "ISMOBILENODE", cpkM, cpBool, &isMobileNode,
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

void RegRequest::forward(Packet * p) {
	click_icmp_echo * icmpheader = (click_icmp_echo *) (p->data() + sizeof(click_ip));
	click_udp * udpheader = (click_udp *) (p->data() + sizeof(click_ip));
	click_ip * oldipheader = (click_ip *) p->ip_header();

	//create new packet
	int offset = 0;
	int tailroom = 0;
	int headroom = sizeof(click_ip);
	int size = headroom + sizeof(click_udp);
	oldipheader->ip_sum = 0;
	if (p->ip_header()->ip_sum != click_in_cksum((const unsigned char *)oldipheader, sizeof(click_ip))) {
		size += sizeof(RegReplyData);
	}
	else {
		size += sizeof(RegRequestData);
	}

	WritablePacket * packet = Packet::make(headroom, 0, size, tailroom);

	if (packet == 0) {
		click_chatter("Failed to make packet");
		p->kill();
		return;
	}

	//set packet to 0
	memset(packet->data(), 0, size);
	//copy old packet to new packet
	memcpy(packet->data(), p->data(), size);

	RegRequestData * oldregrequest = (RegRequestData *) (p->data() + sizeof(click_ip) + sizeof(click_udp));

	click_ip * ipheader = (click_ip *) packet->data();
	click_udp * oldudpheader = (click_udp *) (p->data() + sizeof(click_ip));

	int oldsum = oldudpheader->uh_sum;
	oldudpheader->uh_sum = 0;
	//validity checks
	if ((oldsum != 0) && (oldsum != click_in_cksum((const unsigned char *) oldudpheader, sizeof(click_udp) + sizeof(RegRequestData)))) {
		click_chatter("FA --- Invalid, non-zero udp checksum: 'silently' discard regrequest.");
		return;
	}
	else if ((oldregrequest->flags & (0x1 << 1)) || (oldregrequest->flags & 0x1)) {
		click_chatter("FA --- Sending error 70 in registration reply.");

		//TODO check if filling reply works with new regreply files
		/*
		ip->ip_src = p->ip_header()->ip_dst;
		ip->ip_dst = p->ip_header()->ip_src;
		checksumIPHeader(ip);
		packet->set_dst_ip_anno(ip->ip_dst);

		click_udp * udp = (click_udp *)(packet->data() + sizeof(click_ip));
		udp->uh_sport = oldudp->uh_sport;
		udp->uh_dport = oldudp->uh_dport;
		udp->uh_ulen = htons(sizeof(click_udp) + sizeof(RegistrationReplyData));
		packet->set_network_header((unsigned char *)ip, sizeof(click_ip) + sizeof(click_udp));

		RegReplyData * regreply = (RegReplyData *)(packet->data() + sizeof(click_ip) + sizeof(click_udp));
		regreply->type = oldrrq->type;
		regreply->code = 70;
		regreply->lifetime = 0xffff;
		regreply->homeAddress = oldrrq->homeAddress;
		regreply->homeAgent = oldrrq->homeAgent;
		regreply->identification = oldrrq->identification;
		HandlerCall::call_write("storeIdentification", String(rr->identification), (Element *)_rr, new ErrorHandler());
		udp->uh_sum = 0;
		udp->uh_sum = click_in_cksum((const unsigned char *)udp, sizeof(click_udp) + sizeof(RegistrationReplyData));

		output(0).push(packet);
		*/
		p->kill();
		return;
	}

	click_chatter("FA --- Forwarding registration request.");

	//update ipheader and regrequest data
	RegRequestData * regrequest = (RegRequestData *) (packet->data() + sizeof(click_ip) + sizeof(click_udp));
	ipheader->ip_src = _gateway;
	ipheader->ip_dst = oldregrequest->homeAgent; // forward to home agent
	ipheader->ip_sum = 0;
	ipheader->ip_sum = click_in_cksum((const unsigned char *) ipheader, sizeof(click_ip));
	packet->set_dst_ip_anno(ip->ip_dst);
	regrequest->care_of_address = _gateway;

	if (ntohs(regrequest->lifetime) > _lifetime) {
		regrequest->lifetime = htons(_lifetime);
	}

	//update udpheader
	click_udp * udpheader = (click_udp *) (packet->data() + sizeof(click_ip));
	packet->set_network_header((unsigned char *) ipheader, sizeof(click_ip) + sizeof(click_udp));
	udpheader->uh_sum = 0;
	udpheader->uh_sum = click_in_cksum((const unsigned char *) udpheader, sizeof(click_udp) + sizeof(RegistrationReplyData));

	output(0).push(packet);
}

bool is_set(unsigned value, unsigned index) {
	return (value & (1 << index)) != 0;
}

void RegRequest::generateRequest(Packet * p) {
	if (time(0) == _lastRequest) {
		reregister.clear();
		reregister.schedule_after_msec(1000);

		return;
	}

	click_icmp_echo * icmp_h = (click_icmp_echo *)(p->data() + sizeof(click_ip));
	click_udp * udph = (click_udp *)(p->data() + sizeof(click_ip));
	click_ip *oldip = (click_ip *)p->ip_header();

	bool isHomeAgent = IPAddress(oldip->ip_src).matches_prefix(_me, IPAddress::make_prefix(24));

	if (isHomeAgent) {
		click_chatter("MN --- Sending deregistration to home agent.");

		reregister.clear();
	} else {
		click_chatter("MN --- Sending registration to foreign agent.");

		reregister.clear();
		reregister.schedule_after_msec(_lifetime * 1000 - 500);
	}

	MobileAgentAdvertisement * maa = (MobileAgentAdvertisement *)(p->data() + sizeof(click_ip) + sizeof(click_icmp_echo) / 2 + sizeof(ICMPRouterAdvertisement));

	//errorhandling
	if (!isHomeAgent && !is_set(maa->flags, 15)) {
		click_chatter("MN --- The FA doesn't support registration.");
	} else if (p->length() > sizeof(click_ip) + sizeof(click_icmp_echo)) {
		int offset = 0;
		int tailroom = 0;
		int headroom = sizeof(click_ip);
		int packetsize = headroom + sizeof(click_udp) + sizeof(RegistrationRequestData);
		WritablePacket * packet = Packet::make(headroom, 0, packetsize, tailroom);

		if (packet == 0) {
			click_chatter("Failed to make packet");
			p->kill();
			return;
		}

		ICMPRouterAdvertisement * ira = (ICMPRouterAdvertisement *)(packet->data() + sizeof(click_ip) + sizeof(click_icmp_echo) / 2);
		int lifetime = ira->lifetime;
		// TODO read and delete from list
		if (agents.find(oldip->ip_dst) != agents.end()) {
			agents.insert(std::pair<struct in_addr, int>(oldip->ip_dst, lifetime));
		}
		else {
			agents.find(oldip->ip_dst)->second = lifetime;
		}

		memset(packet->data(), 0, packetsize);

		click_ip * ip = initIPHeader(packet, (click_ip *)(packet->data() + offset), packetsize, 17, ctr, 128, _me, oldip->ip_src);
		offset += sizeof(click_ip);

		click_udp * udp = (click_udp *)(packet->data() + offset);
		udp->uh_sport = htons(1337);
		udp->uh_dport = htons(434);
		udp->uh_ulen = htons(sizeof(click_udp) + sizeof(RegistrationRequestData));
		offset += sizeof(click_udp);
		packet->set_network_header((unsigned char *)ip, sizeof(click_ip) + sizeof(click_udp));

		RegistrationRequestData *rr = (RegistrationRequestData *)(packet->data() + offset);
		rr->type = 1;
		rr->flags = 1 << 6;

		if (isHomeAgent) {
			rr->lifetime = 0;
		}
		else {
			rr->lifetime = htons(_lifetime);
		}

		rr->homeAddress = oldip->ip_dst;
		rr->homeAgent = _gateway;
		memcpy(&rr->careOfAddress, (IPAddress *)(p->data() + sizeof(click_ip) + sizeof(click_icmp_echo) / 2 + sizeof(ICMPRouterAdvertisement) + sizeof(MobileAgentAdvertisement)), sizeof(IPAddress));
		rr->identification = htons(++ctr);

		udp->uh_sum = 0;
		udp->uh_sum = click_in_cksum((const unsigned char *)udp, sizeof(click_udp) + sizeof(RegistrationRequestData));

		output(0).push(packet);

		_lastRequest = time(0);
	}
}

void RegRequest::run_timer(Timer * timer) {
	if (_currentAgent == 0) {
		click_chatter("Mobile Node -- Looking for an agent, trying to connect with it.");
	} else {
		click_chatter("Mobile Node -- Lost connection to my current agent, trying to reconnect.");
	}

	HandlerCall::call_write("solicit", (Element *)_sol, new ErrorHandler());
}

void RegRequest::reRegister() {
	click_chatter("Mobile Node -- Registration timed out, re-registrating...");

	_registrated = false;

	if (_lastP != 0) {
		generateRequest(_lastP);

		reregister.clear();
		reregister.schedule_after_msec(_lifetime * 1000 - 500);
	}
}

void RegRequest::lifetime(int lifetime) {
	if (_lastP) {
		bool isHomeAgent = IPAddress(_lastP->ip_header()->ip_src).matches_prefix(_me, IPAddress::make_prefix(24));

		if (!isHomeAgent && lifetime != 0) {
			if (lifetime != _lifetime) {
				if (lifetime > _lifetime) {
					lifetime = _lifetime;
				}
				// As our lifetime was changed, we must start counting again!
				reregister.clear();
				reregister.schedule_after_msec(lifetime * 1000 - 500);
			}

			_registrated = true;

			click_chatter("Mobile Node -- Registration succesful!");
		} else {
			_registrated = false;

			click_chatter("Mobile Node -- Deregistration succesful!");
		}
	}
}

int doLifetime(const String & data, Element * element, void * user_data, ErrorHandler * error) {
	((RegistrationRequest *)element)->lifetime(atoi(data.c_str()));
}

void RegRequest::add_handlers() {
	int data = 0;
	add_write_handler("lifetime", doLifetime, data, 0);
}

void RegRequest::push(int, Packet *p) {
	if (isMobileNode) {
		ICMPRouterAdvertisement * ira = (ICMPRouterAdvertisement *)(p->data() + sizeof(click_ip) + sizeof(click_icmp_echo) / 2);

		if (_currentAgent == 0 || _currentAgent->hashcode() != IPAddress(p->ip_header()->ip_src).hashcode()) {
			if (_currentAgent == 0) {
				click_chatter("MN --- Connected to an agent, registrating...");
			} else {
				click_chatter("MN --- Found a different agent, (de)registrating...");
			}

			if (_currentAgent != 0) {
				delete _currentAgent;
			}
			_currentAgent = new IPAddress(p->ip_header()->ip_src);

			if (_lastP != 0) {
				_lastP->kill();
			}
			_lastP = 0;
		}

		timer.clear();
		timer.schedule_after_msec(ntohs(ira->lifetime) * 1000);

		int sequenceNumber = ((click_icmp_echo *)p->data() + sizeof(click_ip))->icmp_sequence;

		if ((sequenceNumber < _lastSequenceNumber && sequenceNumber < 255) || _lastP == 0) {
			_registrated = false;

			generateRequest(p);

			_lastP = p;
		}

		_lastSequenceNumber = sequenceNumber;
	} else {
		//we're a foreign agent, so we forward the request to the home agent
		forward(p);
		p->kill();
	}
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RegRequest)
