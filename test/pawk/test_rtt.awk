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
    time_sent[$.TCP.seq""] = $.PKT.ts
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
        avg_rtt = avg_rtt + $.PKT.ts - time_sent[($.TCP.ackno - 1)""]
        num_samples = num_samples + 1
    }
}

END {
    print "The average RTT is ", avg_rtt / num_samples
}
