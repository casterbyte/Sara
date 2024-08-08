# Vex: RouterOS Security Inspector


Autonomous RouterOS configuration analyzer to find security issues. No networking required, only read configurations.

![](/banner/banner.png)

```
Vex: RouterOS Security Inspector
Designed for security engineers

Author: Magama Bazarov, <caster@exploit.org>
Pseudonym: Caster
Version: 1.1
```

# Disclaimer

The tool is intended solely for analyzing the security of RouterOS hardware. The author is not responsible for any damage caused by using this tool

-------------
# Operating

It is written in Python 3 and its work is based on looking for certain elements in configurations that may indicate RouterOS network security issues. The search for suspicious elements is performed using regular expressions.

The tool performs 18 tests:

```
1. Displays information about RouterOS version, device model, serial number
2. Checks the settings of neighbor discovery protocols
3. Checks the status of the Bandwidth Server
4. Checks DNS & DDNS settings
5. Checking the UPnP status
6. Checking SSH status
7. Checking for SOCKS
8. Checking the status of ROMON
9. Check MAC Telnet Server
10. Check MAC Winbox Server
11. Check MAC Ping Server
12. Verifying VRRP authentication
13. Checking SNMP settings
14. OSPF Security check
15. Checking password requirements settings
16. Checking the PoE status
17. Checking SMB activity
18. Checking RMI interfaces
```

> Warning: For a complete RouterOS check, it is recommended to export the configuration using `export verbose` to unload the entire configuration

--------

# Usage

```bash
caster@kali:~$ sudo apt install git python3-colorama
caster@kali:~$ git clone https://github.com/casterbyte/Vex
caster@kali:~$ cd Vex/
caster@kali:~/Vex$ sudo python3 setup.py install
caster@kali:~$ vex
```

```
sage: vex.py [-h] --config CONFIG

Vex: RouterOS Security Inspector

options:
  -h, --help       show this help message and exit
  --config CONFIG  Path to the RouterOS configuration file
```

To perform a configuration analysis, you must supply the RouterOS configuration file as input. This is done with the `--config` argument:

```bash
caster@kali:~$ vex --config routeros.conf
```

Here is an example of the analyzed config:

```
[*] Config Analyzing...
------------------------------
[+] Device Information:
[*] Software ID: BGM1-F15F
[*] Model: C52iG-5HaxD2HaxD
[*] Serial Number: XGB15HBGP01
------------------------------
[+] Discovery Protocols:
[!] Warning: Discovery protocols are enabled on all interfaces
[*] Impact: Information Gathering
------------------------------
[+] Bandwidth Server:
[!] Warning: Bandwidth Server is enabled
[*] Impact: Potential misuse for traffic analysis and network performance degradation
------------------------------
[+] DNS Settings:
[!] Warning: Router is configured as a DNS server
[*] Impact: DNS Flood
[*] Recommendation: Consider closing this port from the internet to avoid unwanted traffic
------------------------------
[+] DDNS Settings:
[!] Warning: Dynamic DNS is enabled
[*] Impact: Exposure to dynamic IP changes and potential unauthorized access
------------------------------
[+] UPnP Settings:
[!] Warning: UPnP is enabled
[*] Impact: Potential unauthorized port forwarding and security risks
------------------------------
[+] SSH Strong Crypto:
[!] Warning: SSH strong crypto is disabled (strong-crypto=no)
[*] Impact: Less secure SSH connections
[*] Recommendation: Enable strong crypto (strong-crypto=yes) for enhanced security. This will use stronger encryption, HMAC algorithms, larger DH primes, and disallow weaker ones
------------------------------
[+] SOCKS Settings:
[!] Warning: SOCKS proxy is enabled
[*] Impact: Potential unauthorized access and misuse of network resources
[*] Recommendation: Disable SOCKS proxy or ensure it is properly secured. SOCKS can be used maliciously if RouterOS is compromised
------------------------------
[+] ROMON Settings:
[!] Warning: ROMON is enabled
[*] Impact: ROMON can be a jump point to other MikroTik devices and should be monitored carefully
[*] Recommendation: Monitor ROMON activities and ensure proper security measures are in place
------------------------------
[+] MAC Ping Server Settings:
[!] Warning: MAC Ping Server is enabled
[*] Impact: Possible unwanted traffic
------------------------------
[+] VRRP Authentication Settings:
[!] Warning: VRRP interface 'vrrp1' has no authentication
[*] Impact: Potential unauthorized access and manipulation of VRRP settings
[*] Recommendation: Configure authentication for VRRP interfaces to prevent unauthorized access
[!] Warning: VRRP interface 'vrrp3' has no authentication
[*] Impact: Potential unauthorized access and manipulation of VRRP settings
[*] Recommendation: Configure authentication for VRRP interfaces to prevent unauthorized access
------------------------------
[+] SNMP:
[!] Warning: SNMP community 'public' is in use
[*] Impact: Information Gathering
[*] Recommendation: Change the community name to something more secure
[!] Warning: SNMP community 'private' is in use
[*] Impact: Information Gathering
[*] Recommendation: Change the community name to something more secure
------------------------------
[+] OSPF Interface Templates Check:
[!] Warning: OSPF interface 'home' is not set to passive
[!] Warning: OSPF interface 'home' has no authentication
[*] Impact: Potential unauthorized access and network disruption
[*] Recommendation: Configure authentication and passive mode for OSPF interfaces to enhance security
[!] Warning: OSPF interface 'ether1' is not set to passive
[!] Warning: OSPF interface 'ether1' has no authentication
[*] Impact: Potential unauthorized access and network disruption
[*] Recommendation: Configure authentication and passive mode for OSPF interfaces to enhance security
[!] Warning: OSPF interface 'ether3' is not set to passive
[!] Warning: OSPF interface 'ether3' has no authentication
[*] Impact: Potential unauthorized access and network disruption
[*] Recommendation: Configure authentication and passive mode for OSPF interfaces to enhance security
------------------------------
[+] Password Strength Requirements:
[!] Warning: No minimum password complexity or length requirements
[*] Recommendation: Set minimum password complexity and length requirements to enhance security
------------------------------
[+] PoE Settings:
[!] Warning: PoE is set to auto-on
[*] Impact: There is a risk of damaging connected devices by unexpectedly supplying power to the port
[*] Recommendation: Review and set PoE settings appropriately
------------------------------
[+] RMI Interfaces Status:
[*] Telnet is enabled - Consider disabling for security reasons
[*] FTP is enabled - Consider disabling for security reasons
[*] WWW (HTTP) is enabled
[*] SSH is enabled
[*] WWW-SSL (HTTPS) is enabled
[*] API is enabled - Consider disabling for security reasons
[*] Winbox is enabled
[*] API-SSL is enabled - Consider disabling for security reasons
[!] Recommendation: Restrict access to RMI only from trusted subnets
```

# Outro

The tool is updated and maintained, suggestions: caster@exploit.org





