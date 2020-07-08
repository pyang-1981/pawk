#PAWK a Packet Capture Analysis Tool
PAWK is a packet capture analysis tool. Different from the well-known Wireshark, it is completely programmable and can do analysis ranging from simple ones such as calculating the RTT (round trip time) to customized complex analysis.

##Overall Workflow
PAWK adopts an AWK-like workflow (it is in fact an extension of GNU AWK with slightly modified syntax) in which the packets in a capture are read one by one. For each packet read, user code is executed to access various information, referred to as network fields (as analogous to normal fields in an AWK record) such as the IP source addresss, of that packet. Inter-packet analysis such as RTT calculation can be done by storing the network fields in some variables for one packet and refer them later when processing another packet.

##Examples
Let's demonstrate the analysis workflow by some examples.

###Naive Average TCP RTT Analysis
Suppose we have a TCP packet capture without any retransmission, that is, every packet is acknowledged immediately. Each RTT sample can be calculated by the time difference between the time when a packet is sent and the time when the corresponding acknowledgment packet is received. Below is the analysis code for calculating the average RTT between two IP addresses 145.254.160.237 (as the sender) and 65.208.228.223 (as the receiver).
```
BEGIN {
    avg_rtt = 0
    num_samples = 0
}

$.IPv4.src_addr == "145.254.160.237" {
    # time_sent is an associative array that
    # stores the time each packet with a certain
    # sequence number is sent. It is indexed
    # by the sequence number.
    # The empty string "" forcefully converts the
    # sequence number to its string representation.
    time_sent[$.TCP.seq""] = $.ts
}
$.IPv4.src_addr == "65.208.228.223" {
    if ($.TCP.ack == 1) {
        avg_rtt = avg_rtt + $.ts - time_sent[($.TCP.ackno - 1)""]
        num_samples = num_samples + 1
    }
}

END {
    print "The average RTT is ", avg_rtt / num_samples
}
```

####Explanation
#####Basic Concepts
For anyone who is familiar with AWK, this piece of code is easy to understand. Just in case you are not familiar with AWK, let's explain it bit by bit.

PAWK code just like AWK code consists of one or more **blocks**, each of which is enclosed by a pair of braces and contains user code. A **block** can have a header, such as *BEGIN*, *END*, etc, specifying on which condition the block will be executed. For example a *BEGIN* block will be executed once when the execution is started and a *END* block will be executed once when the execution is finished. Besides *BEGIN* and *END*, any valid boolean expression can serve as a header. If the expression is evaluated to **true**, the corresponding block will be executed for the current packet. For example the header *$.IPv4.src_addr == "65.208.228.223"* specifies that the block will only be executed if the IPv4 source address of the current packet is *"65.208.228.223"*.

Different from AWK code, PAWK code adds some new syntax to access the network fields of the current packet. *\$* refers to the current packet. A network field can be accessed by *\$.protocol.field*. For example, *\$.TCP.ack* refers to the *ack* bit of the *TCP* protocol of the current packet. The only exception to this naming convention are the packet level fields which are accessed by *\$.field*, such as *\$.ts* which is the timestamp of the current packet. These packet level fields do not belong to any specific protocol.

For a detailed description of all the available network fields, please refer to the documentation linked at the end of this README.

Finally, any thing begins with *#* and all the way to the end of the line is a comment and is ignored when running.

#####RTT Calculation Algorithm
In the above code, we initialize two variables *avg_rtt* which holds the average RTT and *num_samples* which holds the number of RTT samples to 0 in the *BEGIN* block.

For a packet sent by *145.254.160.237*, we execute the code block with the corresponding header. In the block, we record the sending time of a packet in an associative array *time_sent* indexed by the sequence number of the packet.

For a packet sent by *65.208.228.223*, the corresponding code block checks whether the TCP ack bit is set, i.e. *\$.TCP.ack == 1*. If yes, the RTT sample is calculated by the difference between the timestamp of the current packet, i.e., *\$.ts*, and the timestamp stored in the array *time_sent*. The index into the array is the sequence number this packet acknowledges, i.e., *\$.TCP.ackno - 1*. The sample is added to the variable *avg_rtt*, and the number of RTT samples is increased by 1, i.e., *num_samples = num_samples + 1*.

Finally, when all the packet are read and processed, the *END* block is executed, which prints the average RTT as *avg_rtt* divided by *num_samples*.

###Average TCP RTT with Retransmission
Now let's consider the TCP restransmission when calculating the average RTT. Each duplicate acknowledgment packet is triggered by a newly sent packet. Thus the time difference between the duplicate acknowledgment packet and the packet it acknowledges is not an accurate RTT measurement. To simplify the problem, let's ignore the RTT calculation when encountering a duplicate acknowledgment packet. Also we need to ignore the first new acknowledgment packet after the duplicate acknowledgment packets, since it is triggered by the retransmission. Below is the improved code for handling the retransmission.
```
BEGIN {
    avg_rtt = 0
    num_samples = 0
}

$.IPv4.src_addr == "145.254.160.237" {
    # time_sent is an associative array that
    # stores the time each packet with a certain
    # sequence number is sent. It is indexed
    # by the sequence number.
    # The empty string "" forcefully converts the
    # sequence number to its string representation.
    time_sent[$.TCP.seq""] = $.ts
}
$.IPv4.src_addr == "65.208.228.223" {
    # seen_acks stores all seen acknowledgment numbers.
    if ($.TCP.ackno"" in seen_acks) {
        # If the current acknowledgment number is already seen,
        # i.e. it is a duplicate, ignore it and read the
        # next packet. Also set the flag duplicate.
        duplicate = 1
        next
    }
    seen_acks[$.TCP.ackno""] = 1
    if (duplicate == 1) {
        # The first new acknowledgment packet
        # after the duplicate acknowledgment
        # packets. Reset the duplicate flag,
        # ignore it and read the next packet.
        duplicate = 0
        next
    }
    if ($.TCP.ack == 1) {
        avg_rtt = avg_rtt + $.ts - time_sent[($.TCP.ackno - 1)""]
        num_samples = num_samples + 1
    }
}

END {
    print "The average RTT is ", avg_rtt / num_samples
}
```

##Invocation
To run the above code against a packet capture, type
```
./pawk -lreadpcap -a -f [script] [pcap]
```
where the *script* is the path to the code, and *pcap* is the path to the packet capture.

##Documentation
PAWK build and installation  
PAWK commandline options  
PAWK network fields and builtin functions  



