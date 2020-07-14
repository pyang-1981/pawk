# PAWK Netowrk Field and Builtin Function Reference
## Supported Network Fields
### Packet Level Network Fields
Packet level network fields include those which are about the whole packet, and are accessed by *\$.PKT.\**, where "*" can be

| Field Name | Details |
| --- | --- |
| ts | Timestamp of the packet recorded by LIBPCAP |
| len | The length of the packet |
| caplen | Then captured length of the packet |

*ts* is the timestamp recored by LIBPCAP when the interface receives or sends the packet (roughly speaking, there will be processing delays), and is the Unix epoch time (since 01/01/1970 00:00:00 UTC) in milliseconds. For the details and pitfalls on how LIBPCAP handles the timestamp, see the [Manpage](https://www.tcpdump.org/manpages/pcap-tstamp.7.html).  
**Note that LIBCAP records the timestamp in seconds, and microseconds since that seconds value. It is converted to milliseconds by PAWK.**

*len* is the length of the packet, and *caplen* is the captured length. For example a packet can have 1000 bytes in total, but only 100 bytes are captured.
