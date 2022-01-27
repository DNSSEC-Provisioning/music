#!/bin/bash

# rm /var/tmp/music.db
# touch /var/tmp/music.db

../sbin/music-cli signer add -s mas.joh --method ddns --address 212.247.165.231 --port 53 --auth alg:keyname:secret 
../sbin/music-cli signer add -s sig.joh --method ddns --address 212.247.165.234 --port 53 --auth alg:keyname:secret 

../sbin/music-cli signergroup add -g Group1

for i in {1..5} ; do 
  ../sbin/music-cli zone add -z foo${i}.se -g Group1 -t debug
done

for i in {1..5} ; do 
  ../sbin/music-cli zone step-fsm -z foo${i}.se 
done

# for i in {1..5} ; do 
#   ../sbin/music-cli zone step-fsm -z foo${i}.se 
# done

../sbin/music-cli signer join -s mas.joh -g Group1


