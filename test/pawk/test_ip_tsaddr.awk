function assert_equal(expected, real) {
    if (expected != real) {
        printf "Expect "expected" Got "real"\n"
        exit -1
    }
}

{
    assert_equal(0, $.IPv4.option[0].copied)
    assert_equal(2, $.IPv4.option[0].class)
    assert_equal(4, $.IPv4.option[0].number)
    assert_equal(36, $.IPv4.option[0].len)
    assert_equal(37, $.IPv4.option[0].ptr)
    assert_equal(2, $.IPv4.option[0].oflw)
    assert_equal(1, $.IPv4.option[0].flg)
    assert_equal("192.168.1.1", $.IPv4.option[0].addr[0])
    assert_equal(63312879, $.IPv4.option[0].ts[0])
    assert_equal("192.168.1.2", $.IPv4.option[0].addr[1])
    assert_equal(63312905, $.IPv4.option[0].ts[1])
    assert_equal("192.168.4.2", $.IPv4.option[0].addr[2])
    assert_equal(63312907, $.IPv4.option[0].ts[2])
    assert_equal("192.168.2.1", $.IPv4.option[0].addr[3])
    assert_equal(63312903, $.IPv4.option[0].ts[3])
    assert_equal(4, $.IPv4.option[0].ts_len)
    exit 0
}
