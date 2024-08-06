import re
import argparse
from colorama import init, Fore, Style

# Colorama
init(autoreset=True)

# Banner
banner = '''                                                                           
                                       .%.      .%.                                       
                                      :@@@:    .%@@-                                      
                                     :@@+@@:  .%@*@@-                                     
                                    :@@- -@@:.@@= .@@=                                    
                                   :@@:   :@@@@=   .@@-                                   
                                  :@@:     =@@+     .@@=                                  
                                 :@@:     :@@@@-     .@@=                                 
                                -@@:     -@@-:@@=     .%@+                                
                               -@@:     =@@-  :@@=     .%@+                               
                              =@@@@@@@@@@@@@@@@@@@@@@@@@@@@=                             
                                      @@%        @@*                             
                                     *@#          #@#                                     
                                    #@#            *@#                                    
                                   #@*              +@%                                   
                                  %@@@@@@@@@@@@@@@@@@@@%                                                                                                                                                                  
'''

print(banner)
print("    Vex: RouterOS Security Inspector")
print("    Designed for security engineers\n")
print("    For documentation visit: " + "https://github.com/casterbyte/Vex\n")
print("    " + Fore.YELLOW + "Author: " + Style.RESET_ALL + "Magama Bazarov, <caster@exploit.org>")
print("    " + Fore.YELLOW + "Pseudonym: " + Style.RESET_ALL + "Caster")
print("    " + Fore.YELLOW + "Version: " + Style.RESET_ALL + "1.1")
print("    " + Fore.WHITE + "CAUTION: " + Fore.YELLOW + "For the tool to work correctly, use the RouterOS configuration from using the" + Fore.WHITE + " export verbose" + Fore.YELLOW + " command\n")

# Device Info
def extract_info(config_content):
    info_found = False
    info = []
    
    software_id_pattern = r'# software id = (\S+)'
    model_pattern = r'# model = (\S+)'
    serial_number_pattern = r'# serial number = (\S+)'

    software_id = re.search(software_id_pattern, config_content)
    model = re.search(model_pattern, config_content)
    serial_number = re.search(serial_number_pattern, config_content)

    if software_id:
        info.append(f"{Style.BRIGHT + Fore.WHITE}[*] Software ID: {Style.BRIGHT + Fore.YELLOW}{software_id.group(1)}{Style.RESET_ALL}")
        info_found = True
    if model:
        info.append(f"{Style.BRIGHT + Fore.WHITE}[*] Model: {Style.BRIGHT + Fore.YELLOW}{model.group(1)}{Style.RESET_ALL}")
        info_found = True
    if serial_number:
        info.append(f"{Style.BRIGHT + Fore.WHITE}[*] Serial Number: {Style.BRIGHT + Fore.YELLOW}{serial_number.group(1)}{Style.RESET_ALL}")
        info_found = True
    
    if info_found:
        print(f"{Fore.CYAN}" + "-" * 30 + Style.RESET_ALL)
        print(f"{Fore.CYAN}[+] Device Information:{Style.RESET_ALL}")
        for line in info:
            print(line)

# Discovery
def check_discovery_settings(config_content):
    discovery_found = False
    discovery_info = []
    
    discovery_pattern = r'/ip neighbor discovery-settings[\s\S]*?set discover-interface-list=all'
    if re.search(discovery_pattern, config_content):
        discovery_info.append(f"{Style.BRIGHT + Fore.RED}[!] Warning: {Style.BRIGHT + Fore.YELLOW}Discovery protocols are enabled on all interfaces{Style.RESET_ALL}")
        discovery_info.append(f"{Style.BRIGHT + Fore.WHITE}[*] Impact: {Style.BRIGHT + Fore.YELLOW}Information Gathering{Style.RESET_ALL}")
        discovery_found = True
    
    if discovery_found:
        print(f"{Fore.CYAN}" + "-" * 30 + Style.RESET_ALL)
        print(f"{Fore.CYAN}[+] Discovery Protocols:{Style.RESET_ALL}")
        for line in discovery_info:
            print(line)

# Bandwidth Server
def check_bandwidth_server(config_content):
    bandwidth_found = False
    bandwidth_info = []
    
    bandwidth_pattern = r'/tool bandwidth-server[\s\S]*?set[\s\S]*?enabled=yes'
    if re.search(bandwidth_pattern, config_content):
        bandwidth_info.append(f"{Style.BRIGHT + Fore.RED}[!] Warning: {Style.BRIGHT + Fore.YELLOW}Bandwidth Server is enabled{Style.RESET_ALL}")
        bandwidth_info.append(f"{Style.BRIGHT + Fore.WHITE}[*] Impact: {Style.BRIGHT + Fore.YELLOW}Potential misuse for traffic analysis and network performance degradation{Style.RESET_ALL}")
        bandwidth_found = True
    
    if bandwidth_found:
        print(f"{Fore.CYAN}" + "-" * 30 + Style.RESET_ALL)
        print(f"{Fore.CYAN}[+] Bandwidth Server:{Style.RESET_ALL}")
        for line in bandwidth_info:
            print(line)

# DNS Check
def check_dns_settings(config_content):
    dns_found = False
    dns_info = []
    
    dns_pattern = r'/ip dns[\s\S]*?set[\s\S]*?allow-remote-requests=yes'
    if re.search(dns_pattern, config_content):
        dns_info.append(f"{Style.BRIGHT + Fore.RED}[!] Warning: {Style.BRIGHT + Fore.YELLOW}Router is configured as a DNS server{Style.RESET_ALL}")
        dns_info.append(f"{Style.BRIGHT + Fore.WHITE}[*] Impact: {Style.BRIGHT + Fore.YELLOW}DNS Flood{Style.RESET_ALL}")
        dns_info.append(f"{Style.BRIGHT + Fore.GREEN}[*] Recommendation: {Style.BRIGHT + Fore.GREEN}Consider closing this port from the internet to avoid unwanted traffic{Style.RESET_ALL}")
        dns_found = True
    
    if dns_found:
        print(f"{Fore.CYAN}" + "-" * 30 + Style.RESET_ALL)
        print(f"{Fore.CYAN}[+] DNS Settings:{Style.RESET_ALL}")
        for line in dns_info:
            print(line)

# UPnP Check
def check_upnp_settings(config_content):
    upnp_found = False
    upnp_info = []
    
    upnp_pattern = r'/ip upnp[\s\S]*?set[\s\S]*?enabled=yes'
    if re.search(upnp_pattern, config_content):
        upnp_info.append(f"{Style.BRIGHT + Fore.RED}[!] Warning: {Style.BRIGHT + Fore.YELLOW}UPnP is enabled{Style.RESET_ALL}")
        upnp_info.append(f"{Style.BRIGHT + Fore.WHITE}[*] Impact: {Style.BRIGHT + Fore.YELLOW}Potential unauthorized port forwarding and security risks{Style.RESET_ALL}")
        upnp_found = True
    
    if upnp_found:
        print(f"{Fore.CYAN}" + "-" * 30 + Style.RESET_ALL)
        print(f"{Fore.CYAN}[+] UPnP Settings:{Style.RESET_ALL}")
        for line in upnp_info:
            print(line)

# DDNS Check
def check_ddns_settings(config_content):
    ddns_found = False
    ddns_info = []
    
    ddns_pattern = r'/ip cloud[\s\S]*?set[\s\S]*?ddns-enabled=yes'
    if re.search(ddns_pattern, config_content):
        ddns_info.append(f"{Style.BRIGHT + Fore.RED}[!] Warning: {Style.BRIGHT + Fore.YELLOW}Dynamic DNS is enabled{Style.RESET_ALL}")
        ddns_info.append(f"{Style.BRIGHT + Fore.WHITE}[*] Impact: {Style.BRIGHT + Fore.YELLOW}Exposure to dynamic IP changes and potential unauthorized access{Style.RESET_ALL}")
        ddns_found = True
    
    if ddns_found:
        print(f"{Fore.CYAN}" + "-" * 30 + Style.RESET_ALL)
        print(f"{Fore.CYAN}[+] DDNS Settings:{Style.RESET_ALL}")
        for line in ddns_info:
            print(line)

# SSH Strong Crypto
def check_ssh_settings(config_content):
    ssh_found = False
    ssh_info = []
    
    ssh_pattern = r'/ip ssh[\s\S]*?set[\s\S]*?strong-crypto=no'
    if re.search(ssh_pattern, config_content):
        ssh_info.append(f"{Style.BRIGHT + Fore.RED}[!] Warning: {Style.BRIGHT + Fore.YELLOW}SSH strong crypto is disabled (strong-crypto=no){Style.RESET_ALL}")
        ssh_info.append(f"{Style.BRIGHT + Fore.WHITE}[*] Impact: {Style.BRIGHT + Fore.YELLOW}Less secure SSH connections{Style.RESET_ALL}")
        ssh_info.append(f"{Style.BRIGHT + Fore.GREEN}[*] Recommendation: {Style.BRIGHT + Fore.GREEN}Enable strong crypto (strong-crypto=yes) for enhanced security. This will use stronger encryption, HMAC algorithms, larger DH primes, and disallow weaker ones{Style.RESET_ALL}")
        ssh_found = True
    
    if ssh_found:
        print(f"{Fore.CYAN}" + "-" * 30 + Style.RESET_ALL)
        print(f"{Fore.CYAN}[+] SSH Strong Crypto:{Style.RESET_ALL}")
        for line in ssh_info:
            print(line)

# SOCKS Check
def check_socks_settings(config_content):
    socks_found = False
    socks_info = []
    
    socks_pattern = r'/ip socks[\s\S]*?set[\s\S]*?enabled=yes'
    if re.search(socks_pattern, config_content):
        socks_info.append(f"{Style.BRIGHT + Fore.RED}[!] Warning: {Style.BRIGHT + Fore.YELLOW}SOCKS proxy is enabled{Style.RESET_ALL}")
        socks_info.append(f"{Style.BRIGHT + Fore.WHITE}[*] Impact: {Style.BRIGHT + Fore.YELLOW}Potential unauthorized access and misuse of network resources{Style.RESET_ALL}")
        socks_info.append(f"{Style.BRIGHT + Fore.GREEN}[*] Recommendation: {Style.BRIGHT + Fore.GREEN}Disable SOCKS proxy or ensure it is properly secured. SOCKS can be used maliciously if RouterOS is compromised.{Style.RESET_ALL}")
        socks_found = True
    
    if socks_found:
        print(f"{Fore.CYAN}" + "-" * 30 + Style.RESET_ALL)
        print(f"{Fore.CYAN}[+] SOCKS Settings:{Style.RESET_ALL}")
        for line in socks_info:
            print(line)

# RMI Check
def rmi_check(config_content):
    ip_service_found = False
    ip_service_info = []

    services = {
        "telnet": r'/ip service[\s\S]*?set telnet[\s\S]*?disabled=no',
        "ftp": r'/ip service[\s\S]*?set ftp[\s\S]*?disabled=no',
        "api": r'/ip service[\s\S]*?set api[\s\S]*?disabled=no',
        "api-ssl": r'/ip service[\s\S]*?set api-ssl[\s\S]*?disabled=no'
    }

    for service, pattern in services.items():
        if re.search(pattern, config_content):
            ip_service_info.append(f"{Fore.WHITE}" + "-" * 15 + Style.RESET_ALL)
            if service == "telnet":
                ip_service_info.append(f"{Style.BRIGHT + Fore.RED}[!] Warning: {Style.BRIGHT + Fore.YELLOW}Telnet service is enabled {Style.BRIGHT + Fore.WHITE}(disabled=no){Style.RESET_ALL}")
                ip_service_info.append(f"{Style.BRIGHT + Fore.WHITE}[*] Impact: {Style.BRIGHT + Fore.YELLOW}Insecure management panel, potential data interception during MITM attack{Style.RESET_ALL}")
                ip_service_info.append(f"{Style.BRIGHT + Fore.GREEN}[*] Recommendation: {Style.BRIGHT + Fore.GREEN}Disable Telnet to secure the router{Style.RESET_ALL}")
                ip_service_found = True

            if service == "ftp":
                ip_service_info.append(f"{Style.BRIGHT + Fore.RED}[!] Warning: {Style.BRIGHT + Fore.YELLOW}FTP service is enabled {Style.BRIGHT + Fore.WHITE}(disabled=no){Style.RESET_ALL}")
                ip_service_info.append(f"{Style.BRIGHT + Fore.WHITE}[*] Impact: {Style.BRIGHT + Fore.YELLOW}Insecure management panel; potential data interception during MITM attack{Style.RESET_ALL}")
                ip_service_info.append(f"{Style.BRIGHT + Fore.GREEN}[*] Recommendation: {Style.BRIGHT + Fore.GREEN}Disable FTP to secure the router{Style.RESET_ALL}")
                ip_service_found = True

            if service == "api":
                ip_service_info.append(f"{Style.BRIGHT + Fore.RED}[!] Warning: {Style.BRIGHT + Fore.YELLOW}API service is enabled {Style.BRIGHT + Fore.WHITE}(disabled=no){Style.RESET_ALL}")
                ip_service_info.append(f"{Style.BRIGHT + Fore.WHITE}[*] Impact: {Style.BRIGHT + Fore.YELLOW}Potential brute force attack{Style.RESET_ALL}")
                ip_service_info.append(f"{Style.BRIGHT + Fore.GREEN}[*] Recommendation: {Style.BRIGHT + Fore.GREEN}Disable API or secure it properly to prevent brute force attacks{Style.RESET_ALL}")
                ip_service_found = True

            if service == "api-ssl":
                ip_service_info.append(f"{Style.BRIGHT + Fore.RED}[!] Warning: {Style.BRIGHT + Fore.YELLOW}API-SSL service is enabled {Style.BRIGHT + Fore.WHITE}(disabled=no){Style.RESET_ALL}")
                ip_service_info.append(f"{Style.BRIGHT + Fore.WHITE}[*] Impact: {Style.BRIGHT + Fore.YELLOW}Potential brute force attack{Style.RESET_ALL}")
                ip_service_info.append(f"{Style.BRIGHT + Fore.GREEN}[*] Recommendation: {Style.BRIGHT + Fore.GREEN}Disable API-SSL or secure it properly to prevent brute force attacks{Style.RESET_ALL}")
                ip_service_found = True

            # Check for unrestricted access
            address_pattern = rf'/ip service[\s\S]*?set {service}[\s\S]*?address=""'
            if re.search(address_pattern, config_content):
                ip_service_info.append(f"{Style.BRIGHT + Fore.RED}[!] Warning: {Style.BRIGHT + Fore.YELLOW}Service has unrestricted access{Style.RESET_ALL}")
                ip_service_info.append(f"{Style.BRIGHT + Fore.RED}[!] Warning: {Style.BRIGHT + Fore.YELLOW}Management interfaces are accessible from any subnet{Style.RESET_ALL}")
                ip_service_info.append(f"{Style.BRIGHT + Fore.GREEN}[*] Recommendation: {Style.BRIGHT + Fore.GREEN}Restrict access to trusted subnets{Style.RESET_ALL}")
                ip_service_found = True

    if ip_service_found:
        print(f"{Fore.CYAN}" + "-" * 30 + Style.RESET_ALL)
        print(f"{Fore.CYAN}[+] RMI Settings:{Style.RESET_ALL}")
        for line in ip_service_info:
            print(line)
# ROMON
def check_romon(config_content):
    romon_info = []

    romon_pattern = r'/tool romon[\s\S]*?set[\s\S]*?enabled=yes'
    if re.search(romon_pattern, config_content):
        romon_info.append(f"{Style.BRIGHT + Fore.RED}[!] Warning: {Style.BRIGHT + Fore.YELLOW}ROMON is enabled{Style.RESET_ALL}")
        romon_info.append(f"{Style.BRIGHT + Fore.WHITE}[*] Impact: {Style.BRIGHT + Fore.YELLOW}ROMON can be a jump point to other MikroTik devices and should be monitored carefully{Style.RESET_ALL}")
        romon_info.append(f"{Style.BRIGHT + Fore.GREEN}[*] Recommendation: {Style.BRIGHT + Fore.GREEN}Monitor ROMON activities and ensure proper security measures are in place{Style.RESET_ALL}")
    else:
        romon_info.append(f"{Style.BRIGHT + Fore.GREEN}[*] ROMON is not enabled{Style.RESET_ALL}")

    if romon_info:
        print(f"{Fore.CYAN}" + "-" * 30 + Style.RESET_ALL)
        print(f"{Fore.CYAN}[+] ROMON Settings:{Style.RESET_ALL}")
        for line in romon_info:
            print(line)

# MAC Telnet Server
def check_mac_server(config_content):
    mac_server_found = False
    mac_server_info = []

    mac_server_pattern = r'/tool mac-server[\s\S]*?set[\s\S]*?allowed-interface-list=all'
    if re.search(mac_server_pattern, config_content):
        mac_server_info.append(f"{Style.BRIGHT + Fore.RED}[!] Warning: {Style.BRIGHT + Fore.YELLOW}MAC Telnet server is active on all interfaces{Style.RESET_ALL}")
        mac_server_info.append(f"{Style.BRIGHT + Fore.WHITE}[*] Impact: {Style.BRIGHT + Fore.YELLOW}This reduces the security of the Winbox interface. Filter access{Style.RESET_ALL}")
        mac_server_found = True

    if mac_server_found:
        print(f"{Fore.CYAN}" + "-" * 30 + Style.RESET_ALL)
        print(f"{Fore.CYAN}[+] MAC Server Settings:{Style.RESET_ALL}")
        for line in mac_server_info:
            print(line)

# MAC Winbox Server
def check_mac_winbox_server(config_content):
    mac_winbox_found = False
    mac_winbox_info = []

    mac_winbox_pattern = r'/tool mac-server mac-winbox[\s\S]*?set[\s\S]*?allowed-interface-list=all'
    if re.search(mac_winbox_pattern, config_content):
        mac_winbox_info.append(f"{Style.BRIGHT + Fore.RED}[!] Warning: {Style.BRIGHT + Fore.YELLOW}MAC Winbox Server is accessible on all interfaces{Style.RESET_ALL}")
        mac_winbox_info.append(f"{Style.BRIGHT + Fore.WHITE}[*] Impact: {Style.BRIGHT + Fore.YELLOW}This reduces the security of the Winbox interface. Filter access{Style.RESET_ALL}")
        mac_winbox_found = True

    if mac_winbox_found:
        print(f"{Fore.CYAN}" + "-" * 30 + Style.RESET_ALL)
        print(f"{Fore.CYAN}[+] MAC Winbox Server Settings:{Style.RESET_ALL}")
        for line in mac_winbox_info:
            print(line)

# MAC Ping Server
def check_mac_ping_server(config_content):
    mac_ping_found = False
    mac_ping_info = []

    mac_ping_pattern = r'/tool mac-server ping[\s\S]*?set[\s\S]*?enabled=yes'
    if re.search(mac_ping_pattern, config_content):
        mac_ping_info.append(f"{Style.BRIGHT + Fore.RED}[!] Warning: {Style.BRIGHT + Fore.YELLOW}MAC Ping Server is enabled{Style.RESET_ALL}")
        mac_ping_info.append(f"{Style.BRIGHT + Fore.WHITE}[*] Impact: {Style.BRIGHT + Fore.YELLOW}Possible unwanted traffic{Style.RESET_ALL}")
        mac_ping_found = True

    if mac_ping_found:
        print(f"{Fore.CYAN}" + "-" * 30 + Style.RESET_ALL)
        print(f"{Fore.CYAN}[+] MAC Ping Server Settings:{Style.RESET_ALL}")
        for line in mac_ping_info:
            print(line)

# VRRP 
def check_vrrp_authentication(config_content):
    vrrp_info = []
    vrrp_pattern = r'/interface vrrp[\s\S]*?set[\s\S]*?authentication=none[\s\S]*?name=(\S+)[\s\S]*?interface=(\S+)[\s\S]*?priority=(\d+)'
    
    matches = re.finditer(vrrp_pattern, config_content)

    for match in matches:
        interface = match.group(2)
        
        vrrp_info.append(f"{Style.BRIGHT + Fore.RED}[!] Warning: {Style.BRIGHT + Fore.YELLOW}VRRP is running without authentication " + Fore.WHITE + "(authentication=none)")        
        vrrp_info.append(f"{Style.BRIGHT + Fore.WHITE}[*] Interface: {Style.BRIGHT + Fore.YELLOW}{interface}{Style.RESET_ALL}")
        vrrp_info.append(f"{Style.BRIGHT + Fore.WHITE}[*] Impact: {Style.BRIGHT + Fore.YELLOW}Lack of authentication allows an attacker to perform MITM (VRRP Spoofing){Style.RESET_ALL}")

    if vrrp_info:
        print(f"{Fore.CYAN}" + "-" * 30 + Style.RESET_ALL)
        print(f"{Fore.CYAN}[+] VRRP Authentication:{Style.RESET_ALL}")
        for line in vrrp_info:
            print(line)

# SNMP Community Check
def check_snmp_community(config_content):
    snmp_found = False
    snmp_info = []

    public_pattern = r'/snmp community[\s\S]*?set[\s\S]*?name=public'
    private_pattern = r'/snmp community[\s\S]*?set[\s\S]*?name=private'
    
    public_match = re.search(public_pattern, config_content)
    private_match = re.search(private_pattern, config_content)

    if public_match:
        snmp_info.append(f"{Style.BRIGHT + Fore.RED}[!] Warning: {Style.BRIGHT + Fore.YELLOW}SNMP community 'public' is in use{Style.RESET_ALL}")
        snmp_info.append(f"{Style.BRIGHT + Fore.WHITE}[*] Impact: {Style.BRIGHT + Fore.YELLOW}Information Gathering{Style.RESET_ALL}")
        snmp_info.append(f"{Style.BRIGHT + Fore.GREEN}[*] Recommendation: {Style.BRIGHT + Fore.GREEN}Change the community name to something more secure{Style.RESET_ALL}")
        snmp_found = True

    if private_match:
        snmp_info.append(f"{Style.BRIGHT + Fore.RED}[!] Warning: {Style.BRIGHT + Fore.YELLOW}SNMP community 'private' is in use{Style.RESET_ALL}")
        snmp_info.append(f"{Style.BRIGHT + Fore.WHITE}[*] Impact: {Style.BRIGHT + Fore.YELLOW}Information Gathering{Style.RESET_ALL}")
        snmp_info.append(f"{Style.BRIGHT + Fore.GREEN}[*] Recommendation: {Style.BRIGHT + Fore.GREEN}Change the community name to something more secure{Style.RESET_ALL}")
        snmp_found = True

    if snmp_found:
        print(f"{Fore.CYAN}" + "-" * 30 + Style.RESET_ALL)
        print(f"{Fore.CYAN}[+] SNMP:{Style.RESET_ALL}")
        for line in snmp_info:
            print(line)

# OSPF Check
def check_ospf_settings(config_content):
    ospf_found = False
    ospf_info = []

    ospf_interface_pattern = r'/routing ospf interface-template[\s\S]*?'
    passive_pattern = r'/routing ospf interface-template[\s\S]*?passive'
    auth_pattern = r'/routing ospf interface-template[\s\S]*?auth='

    ospf_interface_match = re.search(ospf_interface_pattern, config_content)
    passive_match = re.search(passive_pattern, config_content)
    auth_match = re.search(auth_pattern, config_content)

    if ospf_interface_match:
        if not passive_match:
            ospf_info.append(f"{Style.BRIGHT + Fore.RED}[!] Warning: {Style.BRIGHT + Fore.YELLOW}No passive interfaces in OSPF configuration{Style.RESET_ALL}")
            ospf_info.append(f"{Style.BRIGHT + Fore.WHITE}[*] Impact: {Style.BRIGHT + Fore.YELLOW}This allows an attacker to connect to the OSPF domain{Style.RESET_ALL}")
            ospf_info.append(f"{Style.BRIGHT + Fore.GREEN}[*] Recommendation: {Style.BRIGHT + Fore.YELLOW}Configure passive interfaces to enhance security{Style.RESET_ALL}")
            ospf_found = True

        if not auth_match:
            ospf_info.append(f"{Style.BRIGHT + Fore.RED}[!] Warning: {Style.BRIGHT + Fore.YELLOW}No authentication in OSPF configuration{Style.RESET_ALL}")
            ospf_info.append(f"{Style.BRIGHT + Fore.WHITE}[*] Impact: {Style.BRIGHT + Fore.YELLOW}This allows unauthorized access to the OSPF domain{Style.RESET_ALL}")
            ospf_info.append(f"{Style.BRIGHT + Fore.GREEN}[*] Recommendation: {Style.BRIGHT + Fore.YELLOW}Configure authentication for OSPF to enhance security{Style.RESET_ALL}")
            ospf_found = True

    if ospf_found:
        print(f"{Fore.CYAN}" + "-" * 30 + Style.RESET_ALL)
        print(f"{Fore.CYAN}[+] OSPF Settings:{Style.RESET_ALL}")
        for line in ospf_info:
            print(line)

# User Settings Check (Pass Length)
def check_user_settings(config_content):
    user_settings_found = False
    user_settings_info = []

    user_settings_pattern = r'/user settings[\s\S]*?set[\s\S]*?minimum-categories=0[\s\S]*?minimum-password-length=0'
    if re.search(user_settings_pattern, config_content):
        user_settings_info.append(f"{Style.BRIGHT + Fore.RED}[!] Warning: {Style.BRIGHT + Fore.YELLOW}No minimum password complexity or length requirements{Style.RESET_ALL}")
        user_settings_info.append(f"{Style.BRIGHT + Fore.GREEN}[*] Recommendation: {Style.BRIGHT + Fore.YELLOW}Set minimum password complexity and length requirements to enhance security{Style.RESET_ALL}")
        user_settings_found = True

    if user_settings_found:
        print(f"{Fore.CYAN}" + "-" * 30 + Style.RESET_ALL)
        print(f"{Fore.CYAN}[+] Password Strength Requirements:{Style.RESET_ALL}")
        for line in user_settings_info:
            print(line)

# PoE Check
def check_poe_settings(config_content):
    poe_found = False
    poe_info = []

    poe_auto_on_pattern = r'/interface ethernet[\s\S]*?poe-out=auto-on'
    poe_forced_on_pattern = r'/interface ethernet[\s\S]*?poe-out=forced-on'

    poe_auto_on_match = re.search(poe_auto_on_pattern, config_content)
    poe_forced_on_match = re.search(poe_forced_on_pattern, config_content)

    if poe_auto_on_match:
        poe_info.append(f"{Style.BRIGHT + Fore.RED}[!] Warning: {Style.BRIGHT + Fore.YELLOW}PoE is set to auto-on{Style.RESET_ALL}")
        poe_info.append(f"{Style.BRIGHT + Fore.WHITE}[*] Impact: {Style.BRIGHT + Fore.YELLOW}There is a risk of damaging connected devices by unexpectedly supplying power to the port{Style.RESET_ALL}")
        poe_info.append(f"{Style.BRIGHT + Fore.GREEN}[*] Recommendation: {Style.BRIGHT + Fore.YELLOW}Review and set PoE settings appropriately{Style.RESET_ALL}")
        poe_found = True

    if poe_forced_on_match:
        poe_info.append(f"{Style.BRIGHT + Fore.RED}[!] Warning: {Style.BRIGHT + Fore.YELLOW}PoE is set to forced-on{Style.RESET_ALL}")
        poe_info.append(f"{Style.BRIGHT + Fore.WHITE}[*] Impact: {Style.BRIGHT + Fore.YELLOW}There is a significant risk of damaging connected devices by unexpectedly supplying power to the port{Style.RESET_ALL}")
        poe_info.append(f"{Style.BRIGHT + Fore.GREEN}[*] Recommendation: {Style.BRIGHT + Fore.YELLOW}Review and set PoE settings appropriately{Style.RESET_ALL}")
        poe_found = True

    if poe_found:
        print(f"{Fore.CYAN}" + "-" * 30 + Style.RESET_ALL)
        print(f"{Fore.CYAN}[+] PoE Settings:{Style.RESET_ALL}")
        for line in poe_info:
            print(line)

# SMB Check
def check_smb_settings(config_content):
    smb_found = False
    smb_info = []

    smb_section_pattern = r'/ip smb\s*set\s.*?enabled=(\w+)'
    match = re.search(smb_section_pattern, config_content)

    if match and match.group(1) == 'yes':
        smb_info.append(f"{Style.BRIGHT + Fore.RED}[!] Warning: {Style.BRIGHT + Fore.YELLOW}SMB is enabled{Style.RESET_ALL}")
        smb_info.append(f"{Style.BRIGHT + Fore.WHITE}[*] Impact: {Style.BRIGHT + Fore.YELLOW}Reading files, potential CVE-2018-7445{Style.RESET_ALL}")
        smb_info.append(f"{Style.BRIGHT + Fore.WHITE}[*] Recommendation: {Style.BRIGHT + Fore.GREEN}Are you sure you want SMB? If you don't need it, turn it off. Be careful{Style.RESET_ALL}")
        smb_found = True
    
    if smb_found:
        print(f"{Fore.CYAN}" + "-" * 30 + Style.RESET_ALL)
        print(f"{Fore.CYAN}[+] SMB Settings:{Style.RESET_ALL}")
        for line in smb_info:
            print(line)

# Main
def main():
    parser = argparse.ArgumentParser(description="Vex: RouterOS Security Inspector")
    parser.add_argument("--config", required=True, type=str, help="Path to the RouterOS configuration file")
    args = parser.parse_args()
    
    config_file = args.config
    
    print(f"{Fore.GREEN}[*] Config Analyzing...{Style.RESET_ALL}")
    try:
        with open(config_file, 'r') as file:
            config_content = file.read()
        extract_info(config_content)
        check_discovery_settings(config_content)
        check_bandwidth_server(config_content)
        check_dns_settings(config_content)
        check_ddns_settings(config_content)
        check_upnp_settings(config_content)
        check_ssh_settings(config_content)
        check_socks_settings(config_content)
        rmi_check(config_content)
        check_romon(config_content)
        check_mac_server(config_content)
        check_mac_winbox_server(config_content)
        check_mac_ping_server(config_content)
        check_vrrp_authentication(config_content)
        check_snmp_community(config_content)
        check_ospf_settings(config_content)
        check_user_settings(config_content)
        check_poe_settings(config_content)
        check_smb_settings(config_content)
    except Exception as e:
        print(f"{Fore.RED}Error reading file: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
