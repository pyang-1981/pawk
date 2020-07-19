function assert_function assert_equal(expected, real) {
    if (expected != real) {
        printf "Expect "expected" Got "real"\n"
        exit -1
    }
}

BEGIN {
    i = 0
}

{
    if (i == 2) {
        exit 0
    }

    if (i == 0) {
        assert_equal(0, and($.IPv4.flag, 1))
        assert_equal(0, and($.IPv4.flag, 2))
        assert_equal(1, and($.IPv4.flag, 4))
        assert_equal(0, $.IPv4.offset)
    }

    if (i == 1) {
        assert_equal(0, and($.IPv4.flag, 1))
        assert_equal(0, and($.IPv4.flag, 2))
        assert_equal(0, and($.IPv4.flag, 4))
        assert_equal(976, $.IPv4.offset)
    }


    ++i
}
