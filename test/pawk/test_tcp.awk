function assert_equal(expected, real) {
    if (expected != real) {
        printf "Expect "expected" Got "real"\n"
        exit -1
    }
}

function normalize_pkt_info(pkt_info, normalized_pkt_info)
{
    for (i in pkt_info) {
        split(pkt_info[i], fields, ",")
        for (f in fields) {
            split(fields[f], field, ":")
            normalized_pkt_info[i][field[1]] = field[2]    
        }
    }
}

BEGIN {
   pkt_info[1] = "src_port:3372,dst_port:80,seq:951057939,ackno:0,resv:0,doff:7,fin:0,syn:1,rst:0,psh:0,ack:0,urg:0,ece:0,cwr:0,ns:0,cwin:8760,chk:49932,urg_ptr:0"
   pkt_info[2] = "src_port:80,dst_port:3372,seq:290218379,ackno:951057940,resv:0,doff:7,fin:0,syn:1,rst:0,psh:0,ack:1,urg:0,ece:0,cwr:0,ns:0,cwin:5840,chk:23516,urg_ptr:0"
   
   normalize_pkt_info(pkt_info, normalized_pkt_info)
   i = 1   
}

{
    for (field_name in normalized_pkt_info[i]) {
        assert_equal(normalized_pkt_info[i][field_name], eval_net_field("TCP."field_name))
    }
    i = i + 1
    if (i > length(normalized_pkt_info)) {
        exit 0
    }
}