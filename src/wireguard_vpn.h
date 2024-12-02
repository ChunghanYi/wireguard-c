#ifndef _WIREGUARD_VPN_H_
#define _WIREGUARD_VPN_H_

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define WG_LOCAL_ADDRESS        IPADDR4_INIT_BYTES(10, 1, 1, 100)
#define WG_LOCAL_NETMASK        IPADDR4_INIT_BYTES(255, 255, 255, 0)

#define WG_LOCAL_NETWORK        IPADDR4_INIT_BYTES(10, 1, 1, 0)

#define WG_CLIENT_PRIVATE_KEY   "oG2ZkGjJ+BcJcuK2q+MgkfmoWEPQfnzZzeWxbq1OynU="
#define WG_CLIENT_PORT          51820

//#define WG_GATEWAY_ADDRESS      IPADDR4_INIT_BYTES(10, 1, 1, 200)  // peer vpn ip address
#define WG_PEER_ADDRESS         IPADDR4_INIT_BYTES(10, 1, 1, 200)  // peer vpn ip address
#define WG_PEER_PUBLIC_KEY      "dZopqlLFIFCSSxIQbI1+f6sCUWlrjj4X19VC7iA34Bs="
#define WG_PEER_PORT            51820
#define WG_ENDPOINT_ADDRESS     IPADDR4_INIT_BYTES(192, 168, 8, 139)

int wireguard_setup(void);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _WIREGUARD_VPN_H_
