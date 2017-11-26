#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ether.h>
#include "RememberEtherSource.hh"

CLICK_DECLS

RememberEtherSource::RememberEtherSource() : seh(0) {}

RememberEtherSource::~RememberEtherSource() {}

int RememberEtherSource::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, cpEnd) < 0) return -1;
	return 0;
}

void RememberEtherSource::push(int port, Packet * p){
	// Set the ethernet destination to the one we saved earlier.
	if (port == 1) {
		WritablePacket * packet = p->uniqueify();

		click_ether * destinationetherheader = (click_ether *) packet->data();
		if (sourceetherheader != 0)
			memcpy(destinationetherheader->ether_dhost, sourceetherheader->ether_shost, 6);

		output(0).push(packet);
	}
	// Remember the ethernet source.
	else {
		sourceetherheader = new click_ether();
		memcpy(sourceetherheader, (click_ether *) p->data(), sizeof(click_ether));
	}

	p->kill();
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RememberEtherSource)
