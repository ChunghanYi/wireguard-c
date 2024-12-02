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
$ cd src <br>
* debug mode <br>
$ __sudo ./wireguard -d /etc/wireguard.conf__ <br>
* daemon mode <br>
$ __sudo ./wireguard -D__ <br>
## Reference codes
  https://github.com/smartalock/wireguard-lwip <br>
## My own blog for wireguard analysis
  https://slowbootkernelhacks.blogspot.com/2020/09/wireguard-vpn.html <br>
