#ifndef CLICK_REGREPLY_HH
#define CLICK_REGREPLY_HH

#include <click/element.hh>
#include <click/ipaddress.hh>
#include <list>
using namespace std;

CLICK_DECLS

struct MobilityBinding
{
	int lifetimeRemaining;
	IPAddress mobileNode;
	IPAddress careOfAddress;
	int identification;
};

struct RegReplyData
{
	uint8_t type;
	uint8_t code;
	uint16_t lifetime;
	IPAddress homeAddress;
	IPAddress homeAgent;
	uint64_t identification;
};

class RegRequest;

class RegReply : public Element
{
private:
	IPAddress _me;
	IPAddress _public;
	bool isHomeAgent;
	bool isMobileNode;
	list<MobilityBinding> mobilityBindings;

	int _lifetime;

	void forward(Packet *);
	void generateReply(Packet *);

	RegRequest * _rr;

	void add_handlers();

	Timer timer;

	int _identification;
public:
	RegReply();

	const char *class_name() const	{ return "RegReply"; }
	const char *port_count() const	{ return "0-1/1"; }
	const char *processing() const	{ return PUSH; }
	int configure(Vector<String> &, ErrorHandler *);

	void push(int, Packet *);

	void run_timer(Timer *);

	void storeIdentification(int);
};

CLICK_ENDDECLS

#endif

