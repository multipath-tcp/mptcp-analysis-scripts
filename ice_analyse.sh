#! /bin/bash

for i in ../mptcp/mptcp_ice_*.pcap ../tcp/tcp_ice_*.pcap; do
	test -f "$i.done" && continue
	./analyze.py -i "$i" -p '_ice' -C -W && date -R > "$i.done"
done
