# MulticastModule

client use `omping 192.168.87.2 192.168.87.3` to test
## TODO
* ~IGMPv2 Timer to send Query ~
* ~autoDeleteMember has cooling time~
* ~IP argument can use string (ex."192.168.87.1")~
* ~when group has member than send query~
* ~deal with groupIP in 224.0.0.1~~~224.0.0.255 (no join group?)~
* test client recv multicast
* smallest IP send query
* according to arp to change MAC address

## Problem
* tuntap's tuntap_get_hwaddr() is wrong