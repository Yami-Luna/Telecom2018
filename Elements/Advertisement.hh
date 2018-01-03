#ifndef CLICK_ADVERTISEMENT_HH
#define CLICK_ADVERTISEMENT_HH

#include <click/element.hh>
#include <click/timer.hh>

CLICK_DECLS

struct ICMPRouterAdvertisement
{
	uint8_t advertisement_count;
	uint8_t address_entry_size;
	uint16_t lifetime;
	IPAddress router_address;
	uint32_t preference_level;
};

struct MobileAgentAdvertisement
{
	uint8_t type;
	uint8_t length;
	uint16_t sequence_number;
	uint16_t registration_lifetime;
	uint16_t flags;
};

class Advertisement : public Element {
private:
	uint16_t ctr;
	IPAddress _source;
	IPAddress _careofaddress;
	bool isHomeAgent;

	Timer timer;

	int _lifetime;
	int _registrationLifetime;

public:
	Advertisement();
	~Advertisement();

	const char *class_name() const { return "Advertisement"; }
	const char *port_count() const { return "0-1/1"; }
	const char *processing() const { return PUSH; }

	int configure(Vector<String> &, ErrorHandler *);

	void push_packet(Packet *, bool);
	void push(int, Packet *);

	void run_timer(Timer *);
};

CLICK_ENDDECLS

#endif

