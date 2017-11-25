#include "ipHeader.hh"

click_DECLS

click_ip * initIPHeader(WritablePacket* packet, click_ip * ip, int packetsize, int proto, int id, int ttl, IPAddress src, IPAddress dst)
{
	ip->ip_v = 4;
	ip->ip_hl = 5;
	ip->ip_tos = 0;
	ip->ip_len = htons(packetsize);
	ip->ip_id = htons(id);
	ip->ip_off = 0;
	ip->ip_ttl = ttl;
	ip->ip_p = proto;
	ip->ip_src = src;
	ip->ip_dst = dst;
	packet->set_dst_ip_anno(ip->ip_dst);

	checksumIPHeader(ip);

	return ip;
}

void checksumIPHeader(click_ip * ip)
{
	ip->ip_sum = 0;
	ip->ip_sum = click_in_cksum((const unsigned char *) ip, sizeof(click_ip));
}

click_ENDDECLS
ELEMENT_PROVIDES(IPHeader)
