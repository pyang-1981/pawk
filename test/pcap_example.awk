@load "readpcap"

{
    print $.ts
}

END { print processed_pkt_num(); }
