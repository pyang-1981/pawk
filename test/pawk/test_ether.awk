function assert_equal(expected, real, msg) {
    if (expected != real) {
        printf "Expect "expected" Got "real"\n"
        exit -1
    }
}

BEGIN {
    pkt_type="request"
}

{
    if (pkt_type == "request") {
        assert_equal("08:00:27:3c:5b:7a", $.Ethernet.dst_addr)
        assert_equal("08:00:27:2b:10:de", $.Ethernet.src_addr)
        pkt_type = "reply"
    } else if (pkt_type == "reply") {
        assert_equal("08:00:27:3c:5b:7a", $.Ethernet.src_addr)
        assert_equal("08:00:27:2b:10:de", $.Ethernet.dst_addr)
        pkt_type = "request"    
    }
    assert_equal(0x0800, $.Ethernet.type)
}
