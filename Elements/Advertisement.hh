#ifndef CLICK_ADVERTISEMENT_HH
#define CLICK_ADVERTISEMENT_HH

#include <click/element.hh>

CLICK_DECLS

struct ICMPRouterAdvertisement
{
	uint8_t num_addr;
	uint8_t address_entry_size;
	uint16_t lifetime;
	IPAddress router_address;
	uint32_t preference;
};

struct MobileAgentAdvertisement
{
	uint8_t type;
	uint8_t length;
	uint16_t seq_nr;
	uint16_t lifetime;
	uint16_t flags;
};

class Advertisement : public Element {
private:
	uint16_t counter;
	IPAddress _srcIP;
	IPAddress _coaIP;
	bool isHomeAgent;

	int _lifetime;
	int _regLifetime;

public:
	Advertisement();
	~Advertisement();

	const char *class_name() const { return "Advertisement"; }
	const char *port_count() const { return "0-1/1"; }
	cont char *processing() const { return PUSH; }

	int configure(Vector<String> &, ErrorHandler *);

	void push_packet(Packet *, bool);
	void push(int, Packet *);
};

CLICK_ENDDECLS

#endif
