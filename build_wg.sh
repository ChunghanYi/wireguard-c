#!/bin/sh

cd src
make clean; make

echo "### output ###"
ls -l wireguard

echo
echo "Caution: You must modify the etc/wireguard.conf file before executing the command."
echo
echo "### how to run(debug mode) ###"
echo "cd src"
echo "sudo ./wireguard -d ../etc/wireguard.conf"

echo
echo "### how to run(daemon mode) ###"
echo "Caution: You must copy the ./etc/wireguard.conf file to the /etc directory before executing the command."
echo "cd src"
echo "sudo ./wireguard -D"
