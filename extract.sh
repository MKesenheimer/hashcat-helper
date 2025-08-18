#!/bin/bash

ls **/cracked.txt | xargs -I{} cat {} | cut -d ':' -f4,5 | sort | uniq >> cracked-sorted.txt
cat cracked-sorted.txt | sort | uniq > cracked-sorted.txt_
mv cracked-sorted.txt_ cracked-sorted.txt
