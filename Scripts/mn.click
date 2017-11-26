// Mobile Node
// The input/output configuration is as follows:
//
// Packets for the network are put on output 0
// Packets for the host are put on output 1

// Input:
//	[0]: packets received from the network
//
// Output:
//	[0]: packets sent to the network
//	[1]: packets destined for the host itself


elementclass MobileNode {
	$address, $gateway, $home_agent |

	// Shared IP input path
	ip :: Strip(14)
		-> CheckIPHeader
		-> rt :: LinearIPLookup(
			$address:ip/32 0,
			$address:ipnet 1,
			255.255.255.255 0,
			0.0.0.0/0 $gateway 1);

	arpq :: ARPQuerier($address);

	// incoming packets
	input	-> HostEtherFilter($address)
		-> etherTee :: Tee(2)
		-> in_cl :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800)
		-> arp_res :: ARPResponder($address)
		-> output;

	in_cl[1]
		-> [1]arpq;

	in_cl[2]
		-> Paint(1)
		-> ip;

	//If we receive an advertisement, we have to remember the ether source so we can send a registration to it
	etherTee[1]
		-> IPFilter(allow ip proto 1 and icmp type9, deny all)
		-> res :: RememberEtherSource;

	//local delivery
	rt[0]	-> local :: Tee(2)
		-> IPFilter(deny src udp port 434, deny dst udp port 434, deny icmp type 9, allow all)
		-> IPPrint("MN --- Received a packet)
		-> [1]output;

	local[1]
		-> localClassifier :: IPClassifier(ip proto 1 and icmp type 9, udp port 434);

	//if we receive an advertisement, we send a registration request (unfinished implementation)
	localClassifier[0]
		-> regrequest :: MNRegRequest()
		-> [0]arpq;

	//if we receive a registration reply, we dump it for now
	localClassifier[1]
		-> Discard;


	rt[1]	-> ipgw :: IPGWOptions($address)
		-> FixIPSrc($address)
		-> ttl :: DecIPTTL
		-> frag :: IPFragmenter(1500)
		-> EtherEncap(0x0800, ???, 00:00:00:00:00:00)
		-> [1]res
		-> output;

	ipgw[1]
		-> ICMPError($address, parameterproblem)
		-> rt;

	ttl[1]
		-> ICMPError($address, timeexceeded)
		-> rt;

	frag[1]
		-> ICMPError($address, unreachable, needfrag)
		-> rt;

	//Send solicitations using handler
	Soliciter :: Solicitation(SRC $address, DST 255.255.255.255)
		-> EtherEncap(0x0800, $address:eth, FF:FF:FF:FF:FF:FF)
		-> [0]output;
}
