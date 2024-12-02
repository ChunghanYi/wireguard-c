# wireguard-c
<span style="color:#d3d3d3">Wireguard VPN - the linux userspace VPN daemon implemented with C</span>
## Generate a wireguard static key(ECC private/public keypair)
$ cd scripts <br>
$ __./genkey.sh__ <br>
-rw-rw-r-- 1 chyi chyi 45 11월 17 09:28 privatekey <br>
-rw-rw-r-- 1 chyi chyi 45 11월 17 09:28 publickey <br>
## How to build
$ __./build_wg.sh__
## How to run
Caution: You must copy the ./etc/wireguard.conf file to the /etc directory before executing the command.<br> 
$ cd src <br>
* debug mode <br>
$ __sudo ./wireguard -d /etc/wireguard.conf__ <br>
* daemon mode <br>
$ __sudo ./wireguard -D__ <br>
## Limitations
  It only works in IPv4 environments.<br>
  Only one tunnel is created (client only).<br>
## Reference codes
  https://github.com/smartalock/wireguard-lwip <br>
  The code is copyrighted under BSD 3 clause Copyright (c) 2021 Daniel Hope (www.floorsense.nz)
## My own blog for wireguard analysis
  https://slowbootkernelhacks.blogspot.com/2020/09/wireguard-vpn.html <br>
  <br>
  (***) WireGuard is a registered trademark of Jason A. Donenfeld.

