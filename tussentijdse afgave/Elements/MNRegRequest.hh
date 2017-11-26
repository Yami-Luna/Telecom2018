#ifndef CLICK_MNREGREQUEST_HH
#define CLICK_MNREGREQUEST_HH

#include <click/element.hh>
#include <click/ipaddress.hh>
#include <click/timer.hh>
#include <map>
#include "Solicitation.hh"

CLICK_DECLS

struct MNRegRequestData
{
	uint8_t type;
	uint8_t flags;
	uint16_t lifetime;
	struct in_addr homeAddress;
	struct in_addr homeAgent;
	struct in_addr careOfAddress;
	uint64_t identification;
};

class MNRegReply;

class MNRegRequest : public Element {
private:
public:
	RegistrationRequest();
	~RegistrationRequest();

	const char *class_name() const { return "RegRequest"; }
	const char *port_count() const { return "1/1"; }
	const char *processing() const { return PUSH; }
	int configure(Vector<String> &, ErrorHandler *);

	void push(int, Packet *);
};

CLICK_ENDDECLS

#endif