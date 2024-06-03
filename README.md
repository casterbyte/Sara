# Vex


Autonomous RouterOS configuration analyzer to find security issues. No networking required, only read configurations.

![](/banner/banner.png)

```
Vex: RouterOS Security Inspector
Designed for security engineers

Author: Magama Bazarov, <caster@exploit.org>
Pseudonym: Caster
Version: 1.0
```

# Disclaimer

The tool is intended solely for analyzing the security of RouterOS hardware. The author is not responsible for any damage caused by using this tool

-------------
# Operating

It is written in Python 3 and its work is based on looking for certain elements in configurations that may indicate RouterOS network security issues. The search for suspicious elements is performed using regular expressions.

Vex performs 23 search steps, these include:

```
1. Discovery Protocols Check: Checks whether discovery protocols (such as LLDP) are enabled on all interfaces;
2. Bandwidth Server Check: Checks whether the Bandwidth Server is enabled;
3. DNS Settings Check: Checks whether remote DNS queries are allowed;
4. DDNS Settings Check: Checks whether Dynamic Domain Name System (DDNS) is enabled;
5. UPnP Settings Check: Checks if UPnP (Universal Plug and Play) is enabled;
6. SSH Settings Check: Checks whether cryptographic settings for SSH are enabled;
7. Firewall Filter Rules Check: Retrieves and displays firewall filter rules;
8. Firewall Mangle Rules Check: Retrieves and displays firewall mangle rules;
9. Firewall NAT Rules Check: Retrieves and displays firewall NAT rules;
10. Firewall Raw Rules Check: Retrieves and displays Raw firewall rules;
11. Routes Check: Retrieves and displays routes;
12. SOCKS Settings Check: Checks if the SOCKS proxy is enabled;
13. IP Services Check: Checks the status of various IP services (Telnet, FTP, API, API-SSL, SSH, Winbox, HTTP, HTTPS);
14. BPDU Guard Settings Check: Checks the BPDU Guard settings for STP protection;
15. ROMON Settings Check: Checks if ROMON is enabled;
16. MAC Telnet Server Check: Checks the MAC Telnet Server settings;
17. MAC Winbox Server Check: Checks the MAC Winbox Server settings;
18. MAC Ping Server Check: Checks the MAC Ping Server settings;
19. DHCP Snooping Settings Check: Checks the DHCP Snooping settings to protect against DHCP attacks;
20. NTP Client Settings Check: Checks the NTP client settings;
21. VRRP Security Check: Checks the VRRP authentication settings;
22. OSPF Security Check: Checks OSPF settings for authentication and passive interfaces;
23. SNMP Security Check: Checks SNMP community settings for insecure values;
```

The tool will not only help can help improve the security of the device, but also help improve the quality of hardening.

> Warning: For a complete RouterOS check, it is recommended to export the configuration using `export verbose` to unload the entire configuration

--------

# Usage

```bash
caster@kali:~$ sudo apt install python3-colorama
caster@kali:~$ git clone https://github.com/casterbyte/Vex
caster@kali:~$ cd Vex/
caster@kali:~/Vex$ python3 vex.py --help
```

```
usage: vex.py [-h] --config CONFIG

options:
  -h, --help       show this help message and exit
  --config CONFIG  RouterOS configuration file name
```

To perform a configuration analysis, you must supply the RouterOS configuration file as input. This is done with the `--config` argument:

```bash
caster@kali:~/Vex$ python3 vex.py --config RouterOS.conf
```

Here is an example of the analyzed config:

```bash
[+] Device Information:
[*] Software ID: 7HD9-Z1QD
[*] Model: C52iG-5HaxD2HaxD
[*] Serial Number: HEB08WY6MPT
------------------------------
[+] Interfaces found:
[*] Type: bridge, Name: home
[*] Type: ethernet, Name: ether1
[*] Type: ethernet, Name: ether2
[*] Type: ethernet, Name: ether3
[*] Type: ethernet, Name: ether4
[*] Type: ethernet, Name: ether5
[*] Type: wifiwave2, Name: wifi1
[*] Type: wifiwave2, Name: wifi2
[*] Type: vrrp, Name: vrrp1
[*] Type: wireguard, Name: wg-outerspace
[*] Type: ethernet, Name: switch1
[*] Type: list, Name: all
[*] Type: list, Name: none
[*] Type: list, Name: dynamic
[*] Type: list, Name: static
[*] Type: list, Name: LAN
[*] Type: lte, Name: default
[*] Type: macsec, Name: default
------------------------------
[+] IP Addresses found:
[*] IP Address: 192.168.0.254/24, Interface: home
[*] IP Address: 10.10.101.71/32, Interface: wg-outerspace
[*] IP Address: 192.168.0.11/24, Interface: vrrp1
------------------------------
[+] Discovery Protocols Check:
[*] Security Warning: detected set discover-interface-list=all. Possible disclosure of sensitive information
------------------------------
[+] Bandwidth Server Check:
[*] Security Warning: detected active Bandwidth Server with 'enabled=yes' setting. Possible unwanted traffic towards Bandwidth Server, be careful
------------------------------
[+] DNS Settings Check:
[*] Security Warning: detected directive 'set allow-remote-requests=yes'. This router is a DNS server, be careful
[*] Router is acting as a DNS server and should restrict DNS traffic from external sources to prevent DNS Flood attacks
------------------------------
[+] DDNS Settings Check:
[*] Warning: DDNS is enabled. If not specifically used, it is recommended to disable it.
------------------------------
[+] UPnP Settings Check:
[*] Security Warning: detected directive 'set enabled=yes'. The presence of active UPnP can be indicative of post-exploitation of a compromised RouterOS, and it can also be the cause of an external perimeter breach. Switch it off
------------------------------
[+] SSH Settings Check:
[*] Security Warning: detected 'strong-crypto=no'. It is recommended to enable strong cryptographic ciphers for SSH
------------------------------
[+] Firewall Filter Rules found:
[*] Rule: add action=accept chain=input comment="Allow Established & Related, Drop Invalid" connection-state=established,related
[*] Rule: add action=drop chain=input connection-state=invalid
[*] Rule: add action=accept chain=forward connection-state=established,related
[*] Rule: add action=drop chain=forward connection-state=invalid
[!] Don't forget to use the 'Drop All Other' rule on the external interface of the router. This helps protect the router from external perimeter breaches.
------------------------------
[+] Firewall Mangle Rules found:
[*] No mangle rules found.
[!] In some scenarios, using the mangle table can help save CPU resources.
------------------------------
[+] Firewall NAT Rules found:
[*] Rule: add action=masquerade chain=srcnat comment="Access to Internet" out-interface=wg-outerspace
------------------------------
[+] Firewall Raw Rules found:
[*] No raw rules found.
------------------------------
[+] Routes:
[*] Route: add distance=1 dst-address=111.111.111.111/32 gateway=192.168.1.1
[*] Route: add dst-address=192.168.54.0/24 gateway=192.168.0.253
[*] Route: add dst-address=0.0.0.0/0 gateway=wg-outerspace
------------------------------
[+] SOCKS Settings Check:
[*] Security Warning: detected directive 'set enabled=yes'. SOCKS proxy can be used as a pivoting tool to access the internal network
------------------------------
[+] IP Services Check:
[*] Security Warning: SSH service is enabled. Filter access, you can use more secure key authentication
[*] Security Warning: API-SSL service is enabled. If not in use, it is recommended to disable it to prevent brute-force attacks
[*] Security Warning: Winbox service is enabled. Winbox is constantly being attacked. Be careful with it, filter access
[*] Security Warning: Telnet service is enabled. Turn it off, it's not safe to operate the equipment with it
[*] Security Warning: API service is enabled. If not in use, it is recommended to disable it to prevent brute-force attacks
[*] Security Warning: HTTP service is enabled. Be careful with web-based control panels. Filter access
[*] Security Warning: HTTPS service is enabled. Be careful with web-based control panels. Filter access
[*] Security Warning: FTP service is enabled. If you don't use FTP, disable it and try not to store sensitive information there
------------------------------
[+] BPDU Guard Settings Check:
[*] Security Warning: detected 'bpdu-guard=no'. It is recommended to enable BPDU Guard to protect STP from attacks
------------------------------
[+] ROMON Settings Check:
[*] Security Warning: ROMON is enabled. Be careful with this. If RouterOS is compromised, ROMON can be jumped to the next MikroTik hardware
------------------------------
[+] MAC Telnet Server Check:
[*] Security Warning: MAC Telnet server is active on all interfaces. This reduces the security of the Winbox interface. Filter access
------------------------------
[+] MAC Winbox Server Check:
[*] Security Warning: MAC Winbox Server is accessible on all interfaces. This reduces the security of the Winbox interface. Filter access
------------------------------
[+] MAC Ping Server Check:
[*] Security Warning: MAC Ping Server is enabled. Possible unwanted traffic
------------------------------
[+] DHCP Snooping Settings Check:
[*] Security Warning: detected 'dhcp-snooping=no'. It is recommended to enable DHCP Snooping to protect the network from DHCP attacks (DHCP Spoofing)
------------------------------
[+] NTP Client Settings Check:
[*] Security Warning: NTP client is enabled. Servers: 0.pool.ntp.org, 1.pool.ntp.org
------------------------------
[+] VRRP Security Check:
[*] No issues found with VRRP authentication settings
------------------------------
[+] OSPF Security Check:
[*] Security Warning: OSPF authentication is not configured. There is a risk of connecting an illegal OSPF speaker
[*] Security Warning: OSPF passive interfaces are not configured. There is a risk of connecting an illegal OSPF speaker
------------------------------
[+] SNMP Security Check:
[*] Security Warning: SNMP community 'public' is set. Information Disclosure is possible. Please change SNMP community string
[*] Security Warning: SNMP community 'private' is set. Information Disclosure is possible. Please change SNMP community string
------------------------------
```

# Outro

This is how RouterOS configuration can be analyzed for security and hardening issues. The tool will be developed and maintained by me.







