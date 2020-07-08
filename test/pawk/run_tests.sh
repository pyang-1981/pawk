export AWKLIBPATH=$(pwd)"/../../extension/.libs"
echo "AWKLIBPATH="$AWKLIBPATH

tests="test_ether.awk,ping.pcap
test_ip.awk,ping.pcap
test_ip_ts.awk,ping_ts.pcap
test_ip_tsaddr.awk,ping_tsaddr.pcap
test_tcp.awk,http.pcap
test_rtt.awk,http.pcap"

for t in $tests; do
        echo $t
        script=`echo "$t" | cut -d ',' -f1`
        pcap=`echo "$t" | cut -d ',' -f2`
        echo "gawk -lreadpcap -a -f $script $pcap"
        ../../gawk -lreadpcap -a -f $script $pcap
        if [ $? -ne 0 ]; then exit -1; fi
done
