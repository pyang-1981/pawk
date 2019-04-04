@load "readpcap"

BEGIN { PROCINFO["readpcap"] = 1 }

{
    print $.ts
}

END { print processed_pkt_num(); }
