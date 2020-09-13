function assert_equal(expected, real) {
    if (expected != real) {
        printf "Expect "expected" Got "real"\n"
        exit -1
    }
}

{
    assert_equal(60, $.IPv4.hdr_len)
    assert_equal(1, $.IPv4.option.len)
    assert_equal(0, $.IPv4.option[0].copied)
    assert_equal(2, $.IPv4.option[0].class)
    assert_equal(4, $.IPv4.option[0].number)
    assert_equal(40, $.IPv4.option[0].len)
    assert_equal(33, $.IPv4.option[0].ptr)
    assert_equal(0, $.IPv4.option[0].oflw)
    assert_equal(0, $.IPv4.option[0].flg)
    assert_equal(13841809, $.IPv4.option[0].ts[0])
    assert_equal(13841772, $.IPv4.option[0].ts[1])
    assert_equal(13841778, $.IPv4.option[0].ts[2])
    assert_equal(13841759, $.IPv4.option[0].ts[3])
    assert_equal(13841759, $.IPv4.option[0].ts[4])
    assert_equal(13841778, $.IPv4.option[0].ts[5])
    assert_equal(13841773, $.IPv4.option[0].ts[6])
    assert_equal(7, $.IPv4.option[0].ts_len)
    exit 0
}
