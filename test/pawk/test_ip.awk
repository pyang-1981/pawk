function assert_equal(expected, real) {
    if (expected != real) {
        printf "Expect "expected" Got "real"\n"
        exit -1
    }
}

{
    assert_equal("192.168.1.1", $.IPv4.src_addr)
    assert_equal("192.168.2.1", $.IPv4.dst_addr)
    assert_equal(20, $.IPv4.hdr_len)
    assert_equal(4, $IPv4.ver)
    assert_equal(0, $IPv4.tos)
    assert_equal(84, $.IPv4.len)
    assert_equal(0x05a2, $.IPv4.id)
    assert_equal(0, $.IPv4.offset)
    assert_equal(2, $.IPv4.flag)
    assert_equal(64, $.IPv4.ttl)
    assert_equal(1, $.IPv4.proto)
    assert_equal(0xb0b4, $.IPv4.csum)

    exit 0
}