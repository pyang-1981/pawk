# PAWK a Packet Capture Analysis Tool
PAWK is a packet capture analysis tool. Different from the well-known Wireshark, it is completely programmable and can do analysis ranging from simple ones such as calculating the RTT (round trip time) to customized complex analysis.

## Overall Workflow
PAWK adopts an AWK-like workflow (it is in fact an extension of GNU AWK with slightly modified syntax) in which the packets in a capture are read one by one. For each packet read, user code is executed to access various information, referred to as network fields (as analogous to normal fields in an AWK record) such as the IP source addresss, of that packet. Inter-packet analysis such as RTT calculation can be done by storing the network fields in some variables for one packet and refer them later when processing another packet.

## Examples
Let's demonstrate the analysis workflow by a example.

### Naive Average TCP RTT Analysis
Suppose we have a TCP packet capture. Each RTT sample can be calculated by the time difference between the time when a packet is sent and the time when the corresponding acknowledgment packet is received. We also want to ignore the duplicate acknowledgment packets, since the RTT samples calculated using them are not accurate. In addition, we ignore the first new acknowledgment packet after the duplicate acknowledgment packets, since it may triggered by a retransmission. Below is the analysis code for calculating the average RTT between two IP addresses 145.254.160.237 (as the sender) and 65.208.228.223 (as the receiver).
```
BEGIN {
    avg_rtt = 0
    num_samples = 0
    duplicate = 0
}

$.IPv4.src_addr == "145.254.160.237" {
    # time_sent is an associative array that
    # stores the time each packet is sent. It is indexed
    # by the next sequence number after the current
    # packet.
    # Special cases: the SYN and FIN packets consume
    # one sequence number, thus the next sequence number
    # is the current sequence number plus 1.
    if ($.TCP.syn == 1 || $.TCP.fin == 1) {
        time_sent[$.TCP.seq + 1] = $.PKT.ts
    } else {
        # Otherwise, the next sequence number is the current
        # sequence number plus the payload bytes.
        time_sent[$.TCP.seq + $.IPv4.len - $.IPv4.hdr_len - $.TCP.doff] = $.PKT.ts
    }
}
$.IPv4.src_addr == "65.208.228.223" {
    if ($.TCP.ack == 0) {
        # It is not an acknowledgment packet.
        # Ignore it and read the next packet.
        next
    }
    # seen_acks stores all seen acknowledgment numbers.
    if ($.TCP.ackno in seen_acks) {
        # If the current acknowledgment number is already seen,
        # i.e. it is a duplicate, ignore it and read the
        # next packet. Also set the flag duplicate.
        duplicate = 1
        next
    }
    seen_acks[$.TCP.ackno] = 1
    if (duplicate == 1) {
        # The first new acknowledgment packet
        # after the duplicate acknowledgment
        # packets. Reset the duplicate flag,
        # ignore it and read the next packet.
        duplicate = 0
        next
    }
    # $.TCP.ackno is the next sequence number of the packet
    # it acknowledges.
    avg_rtt = avg_rtt + $.PKT.ts - time_sent[$.TCP.ackno]
    num_samples = num_samples + 1
}

END {
    print "The average RTT is ", avg_rtt / num_samples
}
```

#### Explanation
##### Basic Concepts
For anyone who is familiar with AWK, this piece of code is easy to understand. Just in case you are not familiar with AWK, let's explain it bit by bit.

PAWK code just like AWK code consists of one or more **blocks**, each of which is enclosed by a pair of braces and contains user code. A **block** can have a header, such as *BEGIN*, *END*, etc, specifying on which condition the block will be executed. For example a *BEGIN* block will be executed once when the execution is started and a *END* block will be executed once when the execution is finished. Besides *BEGIN* and *END*, any valid boolean expression can serve as a header. If the expression is evaluated to **true**, the corresponding block will be executed for the current packet. For example the header *$.IPv4.src_addr == "65.208.228.223"* specifies that the block will only be executed if the IPv4 source address of the current packet is *"65.208.228.223"*.

Different from AWK code, PAWK code adds some new syntax to access the network fields of the current packet. *\$* refers to the current packet. A network field can be accessed by *\$.protocol.field*. For example, *\$.TCP.ack* refers to the *ack* bit of the *TCP* protocol of the current packet. For the network fields that do not belong to any protocol, such as the timestamp, we assume they belong to a fictional protocol called *PKT*.

For a detailed description of all the available network fields, please refer to the documentation linked at the end of this README.

Finally, any thing begins with *#* and all the way to the end of the line is a comment and is ignored when running.

##### RTT Calculation Algorithm
In the above code, we initialize three variables to 0 in the *BEGIN* block: *avg_rtt* which holds the average RTT, *num_samples* which holds the number of RTT samples, and *duplicate* which indicates whether the previous acknowledgment packet is a duplicate or not.

For a packet sent by *145.254.160.237*, we execute the code block with the corresponding header. In the block, we record the sending timestamp *\$.PKT.ts* of a packet in an associative array *time_sent* indexed by the next sequence number after the packet. For SYN and FIN packets, the next sequence number is the current sequence number, accessed by *\$.TCP.seq*, plus 1. Otherwise, it is the current sequence number plus the byte size of the payload which is calculated as the IPv4 packet length, i.e. *\$.IPv4.len*,  minus the IPv4 header length, i.e. *\$.IPv4.hdr_len*, then minus the TCP header length, i.e. *\$.TCP.doff*.

For a packet sent by *65.208.228.223*, the corresponding code block checks whether the packet is a valid acknowledgment packet by checking the ACK bit of the TCP header, i.e. *\$.TCP.ack*. If it is cleared, then the packet is not acknowledgment packet and is ignored, the next packet is read. It also ignores the duplicate acknowledgment packets by checking whether the acknowledgment number is in the associative array *seen_acks* which is indexed by all seen acknowledgment numbers. In addition it ignores the first new acknowledgment packet by checking the flag *duplicate*. If the packet is not ignored, the RTT sample is calculated by the difference between the timestamp of the current packet, i.e., *\$.PKT.ts*, and the timestamp stored in the array *time_sent*. The index into the array is the sequence number this packet acknowledges, i.e., *\$.TCP.ackno*. The sample is added to the variable *avg_rtt*, and the number of RTT samples is increased by 1, i.e., *num_samples = num_samples + 1*.

Finally, when all the packet are read and processed, the *END* block is executed, which prints the average RTT as *avg_rtt* divided by *num_samples*.

## Invocation
To run the above code against a packet capture, type
```
pawk -lreadpcap -a -f [script] [pcap]
```
where the *script* is the path to the code, and *pcap* is the path to the packet capture.

## Documentation
PAWK build and installation  
PAWK commandline options  
PAWK tutorial  
PAWK network fields and builtin functions  
