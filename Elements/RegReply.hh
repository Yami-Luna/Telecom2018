#ifndef CLICK_REGREPLY_HH
#define CLICK_REGREPLY_HH

#include <click/element.hh>
#include <click/ipaddress.hh>
#include <list>
using namespace std;

CLICK_DECLS

// Do we need this ? 
struct MobilityBinding {
	int lifetimeRemaining;
	IPAddress mobileNode;
	IPAddress careOfAddress;
	int id;
};

struct RegReplyData {
	uint8_t type;
	uint8_t code;
	uint16_t lifetime;
	IPAddress homeAddress;
	IPAddress homeAgent;
	uint64_t id;
};

class RegRequest;

class RegReply : public Element {
  private:
  	IPAddress publicIP;
	IPAddress selfIP;
	bool isHome;
	bool isMobile;
	list<MobilityBinding> mobilityBindings;
	int id;
	int lifetime;
	Timer timer;
	RegistrationRequest* regRequest;

	void forward(Packet*);
	void generateReply(Packet*);
	void add_handlers();


  public:
	RegReply();

	const char *class_name() const	{ return "RegReply"; }
	const char *port_count() const	{ return "1-2/1-3"; }
	const char *processing() const	{ return PUSH; }
	int configure(Vector<String> &, ErrorHandler *);

	void push(int, Packet *);
	void startTimer(Timer *);
	void keepId(int);
};

CLICK_ENDDECLS

#endif
