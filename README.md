# Sara: RouterOS Security Inspector

It is a autonomous RouterOS configuration analyzer for finding security issues on MikroTik hardware.

```
    _____                 
   / ____|                
  | (___   __ _ _ __ __ _ 
   \___ \ / _` | '__/ _` |
   ____) | (_| | | | (_| |
  |_____/ \__,_|_|  \__,_|  v1.0

    RouterOS Security Inspector. Designed for Security Professionals

    Author: Magama Bazarov, <caster@exploit.org>
```

# Mechanism

This tool is written in Python 3 and uses regular expressions to look for specific values in configurations to detect a problem. As of v1.0, the tool performs 20 security checks, including:

1. **SMB Service Detection**: Identifies if the SMB service is enabled, which may expose the device to vulnerabilities like CVE-2018-7445;

2. **RMI Services Analysis**: Examines active Remote Management Interface (RMI) services such as Telnet, FTP, SSH, and others. The tool warns about unsafe services and provides recommendations for securing them;

3. **UPnP Status Check**: Detects if Universal Plug and Play (UPnP) is enabled, which can open up the network to unauthorized access;
4. **WiFi Configuration Review**: Analyzes WiFi settings for vulnerabilities, including insecure authentication methods, enabled WPS, and PMKID exposure;
5. **DNS Configuration Review**: Checks DNS settings, looking for remote DNS requests being allowed and the absence of DNS over HTTPS (DoH);
6. **Dynamic DNS (DDNS) Status**: Identifies if DDNS is enabled, which might expose your network to unnecessary risks;
7. **Power over Ethernet (PoE) Settings Review**: Analyzes PoE configurations to ensure power management does not pose risks to connected devices;
8. **Protected RouterBOOT Check**: Ensures that Protected RouterBOOT is enabled, preventing unauthorized changes to the bootloader settings;
9. **SOCKS Proxy Detection**: Identifies if a SOCKS proxy is enabled, which could indicate a compromised device;
10. **Bandwidth Server Check**: Detects if the Bandwidth Server is enabled, which could lead to unwanted traffic on the network;
11. **OSPF Interface Analysis**: Examines OSPF interface settings for missing passive mode and authentication, both of which are crucial for securing OSPF communications;
12. **VRRP Interface Analysis**: Checks for VRRP interfaces that lack proper authentication, potentially exposing the network to Man-in-the-Middle (MITM) attacks;
13. **Discovery Protocols Configuration**: Reviews the settings for network discovery protocols, ensuring they are limited to trusted interfaces;
14. **User Password Policy Check**: Analyzes user password policies to ensure they meet security best practices;
15. **SSH Strong Crypto Detection**: Detects if SSH is configured with weak cryptography, providing advice on how to secure it;
16. **Connection Tracking Status**: Reviews the connection tracking settings, advising on when it might be beneficial to disable it;
17. **RoMON Status Check**: Detects if RoMON is enabled, highlighting the need for careful management to prevent unauthorized access to other RouterOS devices;
18. **MAC Server Settings Review**: Analyzes MAC Server and MAC Winbox settings, recommending restrictions to enhance security;
19. **SNMP Analysis**: Identifies the use of default or weak SNMP community strings, which could lead to information gathering attacks;
20. **Port Forwarding Rules Check**: Detects port forwarding rules (dst-nat), warning about potential exposure of internal services to the internet.

# Usage

To install Sara:

```bash
caster@kali:~$ sudo apt install python3-colorama git
caster@kali:~$ git clone https://github.com/casterbyte/Sara
caster@kali:~/Sara$ sudo python3 setup.py install
caster@kali:~$ sara                                            

    _____                 
   / ____|                
  | (___   __ _ _ __ __ _ 
   \___ \ / _` | '__/ _` |
   ____) | (_| | | | (_| |
  |_____/ \__,_|_|  \__,_|  v1.0

    RouterOS Security Inspector. Designed for Security Professionals

    Author: Magama Bazarov, <caster@exploit.org>

    It's recommended to provide a configuration file exported using the 'export verbose' command

usage: sara [-h] --config-file CONFIG_FILE
sara: error: the following arguments are required: --config-file
```

Sara uses just one argument, it is the name/path to the RouterOS configuration file:

```bash
caster@kali:~$ sara --config-file routeros.txt

    _____                 
   / ____|                
  | (___   __ _ _ __ __ _ 
   \___ \ / _` | '__/ _` |
   ____) | (_| | | | (_| |
  |_____/ \__,_|_|  \__,_|  v1.0

    RouterOS Security Inspector. Designed for Security Professionals

    Author: Magama Bazarov, <caster@exploit.org>

    It's recommended to provide a configuration file exported using the 'export verbose' command

[*] Analyzing the configuration file: /mnt/hgfs/Development/Sara/routeros.txt (36.38 KB)

[+] Device Information
    [*] RouterOS Version: X.XX.X
    [*] Model: XXXX-XXXXXXXXXX
    [*] Serial Number: XXXXXXXXXXX
```

# Outro

Sara will be maintained and updated, suggestions: caster@exploit.org



