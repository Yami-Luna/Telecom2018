#ifndef CLICK_REGREQUEST_HH
#define CLICK_REGREQUEST_HH

#include <click/element.hh>
#include <click/ipaddress.hh>
#include <click/timer.hh>
#include <map>
#include "Solicitation.hh"

CLICK_DECLS

struct RegRequestData
{
	uint8_t type;
	uint8_t flags;
	uint16_t lifetime;
	struct in_addr home_address;
	struct in_addr home_agent;
	struct in_addr care_of_address;
	uint64_t identification;
};

struct addressComparator2 : public std::binary_function<struct in_addr, struct in_addr, bool> {
	bool operator() (struct in_addr x, struct in_addr y) const {
		return (IPAddress(x).addr() - IPAddress(y).addr()) < 0;
	}
};

typedef std::map<struct in_addr, int, addressComparator2> agentsMap;

class RegReply;

class RegRequest : public Element {
private:
	IPAddress _gateway;
	IPAddress _me;
	uint16_t ctr;
	bool isMobileNode;
	agentsMap agents;

	IPAddress * _currentAgent;

	void forward(Packet * p);
	void generateRequest(Packet * p);

	Timer timer;
	Timer reregister;

	int _lastRequest;
	int _lastSequenceNumber;

	Solicitation * _sol;

	int _lifetime;

	Packet * _lastP;

	void add_handlers();

	bool _registrated;

	RegistrationReply * _rr;

public:
	RegistrationRequest();
	~RegistrationRequest();

	const char *class_name() const { return "RegRequest"; }
	const char *port_count() const { return "1/1"; }
	const char *processing() const { return PUSH; }
	int configure(Vector<String> &, ErrorHandler *);

	void push(int, Packet *);
	void run_timer(Timer *);

	void reRegister();
	void lifetime(int);
};

CLICK_ENDDECLS

#endif