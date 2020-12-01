# Netlogon-Client
A Netlogon Client wrote by [Raefko](https://github.com/raefko) to test some RPC calls to Netlogon during my internship at ALSID.
It uses my fork of [Impacket](https://github.com/raefko/impacket).

```Usage: netlogon_client.py <dc-name> <account_name> <account_password_hash> <dc-ip>```

It can call some functions, but not all of them. It will be updated soon.

![](https://i.imgur.com/5dXAL1l.png)
![](https://i.imgur.com/5daPiAY.png)


Example of calling the ```hNetrLogonGetCapabilities``` (32):
![](https://i.imgur.com/oWXXREB.png)


The user class contains some parameters needed in most of the functions.
You can use ```skip.``` to put a `NULL` value.
