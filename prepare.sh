#!/bin/bash

rm -f eduroam_* SySS* DIRECT* KaeseWLAN_* RobbieCookFiftytwo_* Audi* 
rm -f hashes.hc22000 wordlist

hcxpcapngtool -o hashes.hc22000 -E wordlist *.pcap
echo $(wc -l wordlist)
sort wordlist | uniq > wordlist.sorted
mv wordlist.sorted wordlist
echo $(wc -l wordlist)

