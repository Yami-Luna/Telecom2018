#ifndef CLICK_REMEMBERETHERSOURCE_HH
#define CLICK_REMEMBERETHERSOURCE_HH

#include <click/element.hh>

CLICK_DECLS

class RememberEtherSource : public Element {
private:
	click_ether * sourceetherheader;
public:
	RememberEtherSource();
	~RememberEtherSource();

	const char *class_name() const	{ return "RememberEtherSource"; }
	const char *port_count() const	{ return "2/1"; }
	const char *processing() const	{ return PUSH; }
	int configure(Vector<String> &, ErrorHandler *);

	void push(int, Packet *);
};

CLICK_ENDDECLS

#endif
