BEGIN {
    avg_rtt = 0
    num_samples = 0
    duplicate = 0
}

$.IPv4.src_addr == "145.254.160.237" {
    # time_sent is an associative array that
    # stores the time each packet with a certain
    # sequence number is sent. It is indexed
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
    if ($.TCP.ack == 1) {
        # $.TCP.ackno is the next sequence number of the packet
        # it acknowledges.
        avg_rtt = avg_rtt + $.PKT.ts - time_sent[$.TCP.ackno]
        num_samples = num_samples + 1
    }
}

END {
    print "The average RTT is ", avg_rtt / num_samples
}
