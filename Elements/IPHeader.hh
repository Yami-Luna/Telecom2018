#ifndef CLICK_MYIPHEADER_HH
#define CLICK_MYIPHEADER_HH

#include <click/config.h>
#include <click/ipaddress.hh>
#include <click/packet.hh>
#include <clicknet/ip.h>

CLICK_DECLS

click_ip * initIPHeader(WritablePacket * packet, click_ip * ip, int packetsize, int proto, int id, int ttl, IPAddress src, IPAddress dst);
void checksumIPHeader(click_ip * ip);

CLICK_ENDDECLS
