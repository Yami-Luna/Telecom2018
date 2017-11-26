#ifndef CLICK_SOLICITATION_HH
#define CLICK_SOLICITATION_HH

#include <click/element.hh>
#include <click/timer.hh>

CLICK_DECLS

class Solicitation : public Element {
private:
	IPAddress src;
	IPAddress dst;
	uint16_t ctr;

	void add_handlers();

public:
	Solicitation();
	~Solicitation();

	const char *class_name() const	{ return "Solicitation"; }
	const char *port_count() const	{ return "0/1"; }
	const char *processing() const	{ return PUSH; }
	int configure(Vector<String> &, ErrorHandler *);

	void sendSolicitation();
};

CLICK_ENDDECLS

#endif
