# Telecom Project Overview

## Abbreviations

* CN : Corresponding Node
= The guy who wants to send you a packet

* MN : Mobile Node
= The guy who will receive the packet, but may or may not be in his usual home location.

* HA : Home Agent
= Usually a router, knows the location of MN.

* FA: Foreign Agent
= If MN is not home, this is the agent of MN's current location

## The Idea In Theory

1. CN sends a packet for MN, so it just sends it to HA.
2. HA gives it to MN if MN is home, otherwise tunnels it to FA.
3. FA sends the packet to MN.

## How it works in Click

In **click/scripts**, there are 5 click files, each doing their part of the implementation.
**glue.click** just glues everything together.
**cn.click** sends out packages using an **ICMPPingSource**.
**fa.click, ha.click, mn.click** are basically small files that put the relevant agent in place.

These agents are the ones we implement, and they can be found in **click/scripts/library**.
These files seem to be the only ones we are allowed to edit.
We also have to create click elements in **click/elements/local/mobileip**

Also, the start_click.sh file doesn't seem to do what it should do.
I'm pretty sure every line needs to end with "&", not just some, so I edited that.

Okay, so **cn.click** sends out some packets (just pings, along with what it seems to tap from tap3? idk),
and puts these on tap3. In **glue.click** we see that these packets on tap3 (from CN) are received.
Then, they are put on **[1]public[1]**, which is a ListenEtherSwitch:

It has N input ports, and N+1 output ports. Any packets that come in are output on their corresponding output port,
AND on the extra output port. This is used to dump the packets received to the dump files.

In **definitions.click** we can see all taps with their respective names:

* tap0: MNode Address
* tap1: HA Private Address
* tap2: HA Public Address
* tap3: CN Address
* tap4: FA Public Address
* tap5: FA Private Address

Now let's take a look at where these are used. When CN sends its packages,
some (it's not clear to me which, but I don't think that matters for us) they are sent to the HA Public Address.
That means we need to implement HA checking if MN is home or not, and then sending it to wither HA Private Address or FA Public address.
Then FA needs to be able to do the same.