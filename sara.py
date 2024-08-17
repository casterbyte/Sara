#!/usr/bin/env python3

import argparse
import re
import colorama
from colorama import Fore, Style

# Colorama
colorama.init(autoreset=True)

def banner():
    banner_text = r"""
    _____                 
   / ____|                
  | (___   __ _ _ __ __ _ 
   \___ \ / _` | '__/ _` |
   ____) | (_| | | | (_| |
  |_____/ \__,_|_|  \__,_|  v1.0
"""
    print(banner_text)
    print("    " + Fore.YELLOW + "RouterOS Security Inspector. Designed for Security Professionals\n")
    print("    " + Fore.YELLOW + "Author: " + Style.RESET_ALL + "Magama Bazarov, <caster@exploit.org>\n")
    print("    " + "It's recommended to provide a configuration file exported using the 'export verbose' command")
    print()

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config-file', required=True, help='Path to the RouterOS configuration file')
    return parser.parse_args()

def extract_device_info(config_data):
    version_pattern = r"#.*by RouterOS (\S+)"
    model_pattern = r"# model = (\S+)"
    serial_pattern = r"# serial number = (\S+)"

    version_match = re.search(version_pattern, config_data)
    model_match = re.search(model_pattern, config_data)
    serial_match = re.search(serial_pattern, config_data)

    if version_match and model_match and serial_match:
        routeros_version = version_match.group(1)
        model = model_match.group(1)
        serial_number = serial_match.group(1)

        print(f"{Style.BRIGHT}[+] Device Information{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    [*] RouterOS Version: {routeros_version}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    [*] Model: {model}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    [*] Serial Number: {serial_number}{Style.RESET_ALL}")
        print()

def check_smb_enabled(config_data):
    smb_pattern = r"/ip smb\s+set.*enabled=yes"
    match = re.search(smb_pattern, config_data)
    if match:
        print(f"{Style.BRIGHT}[+] Checking SMB{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    [!] Warning: SMB service is enabled. Are you sure you want to do this? Also possible CVE-2018-7445{Style.RESET_ALL}")
        print(f"{Fore.GREEN}    [*] Solution: Turn off SMB or if you need it, filter access to it{Style.RESET_ALL}")
        print()

def check_rmi_services(config_data):
    rmi_services = {
        'telnet': r"set telnet address=.* disabled=(no|yes)",
        'ftp': r"set ftp address=.* disabled=(no|yes)",
        'www': r"set www address=.* disabled=(no|yes)",
        'ssh': r"set ssh address=.* disabled=(no|yes)",
        'www-ssl': r"set www-ssl address=.* disabled=(no|yes)",
        'api': r"set api address=.* disabled=(no|yes)",
        'winbox': r"set winbox address=.* disabled=(no|yes)",
        'api-ssl': r"set api-ssl address=.* disabled=(no|yes)",
    }
    
    active_services = []
    unsafe_services = ['ftp', 'www', 'telnet']
    caution_services = ['www-ssl', 'winbox', 'ssh']
    
    for service, pattern in rmi_services.items():
        match = re.search(pattern, config_data)
        if match:
            disabled_status = re.search(r"disabled=(no|yes)", match.group(0)).group(1)
            if disabled_status == 'no':
                active_services.append(service)
    
    if active_services:
        print(f"{Style.BRIGHT}[+] Checking RMI Services{Style.RESET_ALL}")
        
        unsafe_active_services = [s for s in active_services if s in unsafe_services]
        if unsafe_active_services:
            print(f"{Fore.RED}    [!] Warning: The following RMI services are enabled and may be unsafe: {', '.join(unsafe_active_services)}.{Style.RESET_ALL}")
        
        caution_active_services = [s for s in active_services if s in caution_services]
        if caution_active_services:
            print(f"{Fore.YELLOW}    [!] Caution: The following RMI services are enabled: {', '.join(caution_active_services)}.{Style.RESET_ALL}")
        
        api_active_services = [s for s in active_services if s in ['api', 'api-ssl']]
        if api_active_services:
            print(f"{Fore.YELLOW}    [!] Note: The following RMI services are enabled and might be susceptible to brute force attacks: {', '.join(api_active_services)}.{Style.RESET_ALL}")

        if unsafe_active_services or caution_active_services or api_active_services:
            print(f"{Fore.GREEN}    [*] Solution: Disable the above RMI services if they are not required for security.{Style.RESET_ALL}")
            print(f"{Fore.CYAN}    [*] Tip: Restrict access to enabled services to trusted subnets only.{Style.RESET_ALL}")
        print()

def check_upnp_enabled(config_data):
    upnp_pattern = r"/ip upnp\s+set.*enabled=yes"
    match = re.search(upnp_pattern, config_data)
    if match:
        print(f"{Style.BRIGHT}[+] Checking UPnP{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    [!] Warning: UPnP is enabled. This can expose your network to various security risks, including unauthorized access.{Style.RESET_ALL}")
        print(f"{Fore.GREEN}    [*] Solution: Disable UPnP unless absolutely necessary, and ensure your firewall is properly configured.{Style.RESET_ALL}")
        print()

def check_wifi_settings(config_data):
    wifi_patterns = [
        r"/interface wifi\s+set \[ find default-name=(.*?) \]\s+(.*?)(?=set \[ find default-name=|\Z)",
        r"/interface wireless\s+set \[ find default-name=(.*?) \]\s+(.*?)(?=set \[ find default-name=|\Z)",
        r"/interface wifiwave2\s+set \[ find default-name=(.*?) \]\s+(.*?)(?=set \[ find default-name=|\Z)"
    ]
    wps_pattern = r"wps=(push-button|disable)"
    pmkid_pattern = r"disable-pmkid=(no|yes)"
    auth_pattern = r"security\.authentication-types=(wpa-psk|wpa2-psk)"

    for wifi_pattern in wifi_patterns:
        wifi_matches = re.findall(wifi_pattern, config_data, re.DOTALL)
        
        if wifi_matches:
            print(f"{Style.BRIGHT}[+] Checking WiFi Settings{Style.RESET_ALL}")
            
            for interface, settings in wifi_matches:
                wps_match = re.search(wps_pattern, settings)
                pmkid_match = re.search(pmkid_pattern, settings)
                auth_match = re.search(auth_pattern, settings)
                
                if wps_match and wps_match.group(1) == 'push-button':
                    print(f"{Fore.YELLOW}    [!] Warning: WPS is enabled on interface {interface}. WPS Pin code can be cracked, brute-forced.{Style.RESET_ALL}")
                    
                if pmkid_match and pmkid_match.group(1) == 'no':
                    print(f"{Fore.YELLOW}    [!] Warning: PMKID is enabled on interface {interface}. PMKID is easy to bruteforce.{Style.RESET_ALL}")

                if auth_match:
                    auth_type = auth_match.group(1)
                    if auth_type in ['wpa-psk', 'wpa2-psk']:
                        print(f"{Fore.YELLOW}    [!] Warning: Interface {interface} is using insecure authentication method '{auth_type}'. WPA/WPA2-PSK are long gone, use WPA2-E, WPA3.{Style.RESET_ALL}")
                
            print()

def check_dns_settings(config_data):
    dns_pattern = r"/ip dns\s+set\s+(.*?)\s+(?=\/ip dns|\Z)"
    allow_remote_requests_pattern = r"allow-remote-requests=(yes|no)"
    use_doh_server_pattern = r"use-doh-server=\"(.*?)\""

    dns_matches = re.findall(dns_pattern, config_data, re.DOTALL)
    
    if dns_matches:
        print(f"{Style.BRIGHT}[+] Checking DNS Settings{Style.RESET_ALL}")
        
        for settings in dns_matches:
            allow_remote_requests_match = re.search(allow_remote_requests_pattern, settings)
            if allow_remote_requests_match and allow_remote_requests_match.group(1) == 'yes':
                print(f"{Fore.YELLOW}    [!] Warning: Router is configured to allow remote DNS requests. Close the DNS UDP/53 port from the Internet.{Style.RESET_ALL}")
            
            use_doh_server_match = re.search(use_doh_server_pattern, settings)
            if use_doh_server_match and use_doh_server_match.group(1) == '':
                print(f"{Fore.YELLOW}    [!] Note: DNS over HTTPS (DoH) is not configured. Consider configuring a DoH server for improved privacy.{Style.RESET_ALL}")
        
        print()

def check_ddns_enabled(config_data):
    pattern = r"/ip cloud\s+set.*ddns-enabled=yes"
    match = re.search(pattern, config_data)
    
    if match:
        print(f"{Style.BRIGHT}[+] Checking DDNS Configuration{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    [!] Warning: DDNS is enabled. Are you sure you need it?{Style.RESET_ALL}")
        print(f"{Fore.GREEN}    [*] Solution: Disable DDNS if it is not required.{Style.RESET_ALL}")
        print()

def check_poe_settings(config_data):
    poe_pattern = r"/interface ethernet\s+set \[ find default-name=(.*?) \]\s+(.*?)(?=set \[ find default-name=|\Z)"
    poe_status_pattern = r"poe-out=(auto-on|forced-on)"
    
    poe_matches = re.findall(poe_pattern, config_data, re.DOTALL)
    
    found_poe = False
    
    for interface, settings in poe_matches:
        poe_status_match = re.search(poe_status_pattern, settings)
        if poe_status_match:
            if not found_poe:
                print(f"{Style.BRIGHT}[+] Checking PoE Settings{Style.RESET_ALL}")
                found_poe = True
            poe_status = poe_status_match.group(1)
            if poe_status in ['auto-on', 'forced-on']:
                print(f"{Fore.YELLOW}    [!] Warning: PoE is enabled on interface {interface} with setting '{poe_status}'. This could supply power to connected devices and potentially damage them if not properly managed.{Style.RESET_ALL}")
    
    if found_poe:
        print()

def check_protected_routerboot(config_data):
    pattern = r"protected-routerboot=(enabled|disabled)"
    match = re.search(pattern, config_data)
    
    if match and match.group(1) == "disabled":
        print(f"{Style.BRIGHT}[+] Checking Protected RouterBOOT{Style.RESET_ALL}")
        print(f"{Fore.RED}    [!] Warning: Protected RouterBOOT is disabled. This may allow unauthorized changes to the bootloader settings.{Style.RESET_ALL}")
        print(f"{Fore.GREEN}    [*] Solution: Enable Protected RouterBOOT to prevent unauthorized access to the bootloader.{Style.RESET_ALL}")
        print()

def check_socks_enabled(config_data):
    pattern = r"/ip socks\s+set.*enabled=yes"
    match = re.search(pattern, config_data)
    
    if match:
        print(f"{Style.BRIGHT}[+] Checking SOCKS Proxy{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    [!] Warning: SOCKS Proxy is enabled. The presence of SOCKS may indicate that the device has been compromised.{Style.RESET_ALL}")
        print(f"{Fore.GREEN}    [*] Solution: Disable SOCKS Proxy if it is not required.{Style.RESET_ALL}")
        print()

def check_bandwidth_server_enabled(config_data):
    pattern = r"/tool bandwidth-server\s+set.*enabled=yes"
    match = re.search(pattern, config_data)
    
    if match:
        print(f"{Style.BRIGHT}[+] Checking Bandwidth Server{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    [!] Warning: Bandwidth Server is enabled. Possible unwanted traffic.{Style.RESET_ALL}")
        print(f"{Fore.GREEN}    [*] Solution: Disable the Bandwidth Server if it is not required.{Style.RESET_ALL}")
        print()

def check_ospf_interfaces(config_data):
    ospf_pattern = r'add\s[^\n]*?interfaces=([\w-]+)[^\n]*'
    matches = re.findall(ospf_pattern, config_data)

    if matches:
        print(f"{Style.BRIGHT}[+] Checking OSPF Interfaces{Style.RESET_ALL}")
        for match in matches:
            interface_block = re.search(rf'add[^\n]*?interfaces={match}[^\n]*', config_data).group(0)
            missing_passive = 'passive' not in interface_block
            missing_auth = 'auth=' not in interface_block
            
            if missing_passive:
                print(f"{Fore.YELLOW}    [!] Warning: OSPF interface '{match}' is not passive. Without passive interfaces, an attacker can hear an OSPF Hello on the air and connect to an OSPF network.{Style.RESET_ALL}")
                print(f"{Fore.GREEN}    [*] Solution: Consider configuring the interface '{match}' as passive to limit OSPF traffic only to necessary interfaces.{Style.RESET_ALL}")
            
            if missing_auth:
                print(f"{Fore.YELLOW}    [!] Warning: OSPF interface '{match}' does not have authentication configured. Without authentication, an attacker can connect to an OSPF network.{Style.RESET_ALL}")
                print(f"{Fore.CYAN}    [*] Tip: When configuring OSPF authentication, use strong passwords, as OSPF password bruteforcing is still possible.{Style.RESET_ALL}")
                print(f"{Fore.GREEN}    [*] Solution: Configure authentication on the interface '{match}' to secure OSPF.{Style.RESET_ALL}")
        print()

def check_vrrp_interfaces(config_data):
    vrrp_pattern = r'add\s[^\n]*?name=([\w-]+)[^\n]*'
    matches = re.findall(vrrp_pattern, config_data)

    if matches:
        found_issue = False
        for match in matches:
            interface_block = re.search(rf'add[^\n]*?name={match}[^\n]*', config_data).group(0)
            missing_auth = 'authentication=none' in interface_block
            
            if missing_auth:
                if not found_issue:
                    print(f"{Style.BRIGHT}[+] Checking VRRP Interfaces{Style.RESET_ALL}")
                    found_issue = True
                print(f"{Fore.YELLOW}    [!] Warning: VRRP interface '{match}' does not have proper authentication configured (authentication=none). An attacker can spoof the VRRP and conduct MITM.{Style.RESET_ALL}")
                print(f"{Fore.CYAN}    [*] Fact: Only the 2 version of VRRP supports authentication configuration. If you use AH - it uses HMAC-MD5.{Style.RESET_ALL}")
                print(f"{Fore.GREEN}    [*] Solution: Configure authentication on the interface '{match}' to secure VRRP.{Style.RESET_ALL}")
        
        if found_issue:
            print()

def check_discovery_protocols(config_data):
    pattern = r"/ip neighbor discovery-settings\s+set.*discover-interface-list=all.*protocol=([\w,]+)"
    match = re.search(pattern, config_data)
    
    if match:
        active_protocols = match.group(1)
        print(f"{Style.BRIGHT}[+] Checking Discovery Protocols{Style.RESET_ALL}")
        print(f"{Fore.RED}    [!] Warning: Discovery Protocols are enabled on all interfaces (discover-interface-list=all). This could expose detailed information about your device to the network.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    [!] Active protocols: {active_protocols}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}    [*] Solution: Limit the discovery protocols to specific interfaces or disable them if not required to enhance security.{Style.RESET_ALL}")
        print()

def check_user_password_policies(config_data):
    pattern = r"/user settings\s+set.*minimum-categories=0.*minimum-password-length=0"
    match = re.search(pattern, config_data)
    
    if match:
        print(f"{Style.BRIGHT}[+] Checking User Password Policies{Style.RESET_ALL}")
        print(f"{Fore.RED}    [!] Warning: Password policies are not properly configured. Both minimum password categories and minimum password length are set to 0.{Style.RESET_ALL}")
        print(f"{Fore.GREEN}    [*] Solution: Set a higher minimum password length and require at least one or more character categories (e.g., uppercase, lowercase, numbers, special characters) for better security.{Style.RESET_ALL}")
        print()

def check_ssh_strong_crypto(config_data):
    pattern = r"/ip ssh\s+set.*strong-crypto=no"
    match = re.search(pattern, config_data)
    
    if match:
        print(f"{Style.BRIGHT}[+] Checking SSH Strong Crypto{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    [!] Warning: SSH is configured with 'strong-crypto=no'. This reduces the security of SSH connections by allowing weaker encryption algorithms.{Style.RESET_ALL}")
        print(f"{Fore.GREEN}    [*] Solution: Set 'strong-crypto=yes' to enhance security. This will: {Style.RESET_ALL}")
        print(f"{Fore.YELLOW}        - Use stronger encryption, HMAC algorithms, and larger DH primes while disallowing weaker ones.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}        - Prefer 256-bit and 192-bit encryption instead of 128 bits.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}        - Disable null encryption.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}        - Prefer sha256 for hashing instead of sha1.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}        - Disable md5.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}        - Use a 2048-bit prime for Diffie Hellman exchange instead of 1024-bit.{Style.RESET_ALL}")
        print()

def check_connection_tracking(config_data):
    pattern = r"/ip firewall connection tracking\s+set.*enabled=(auto|yes)"
    match = re.search(pattern, config_data)
    
    if match:
        enabled_value = match.group(1)
        print(f"{Style.BRIGHT}[+] Checking Connection Tracking{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    [!] Connection Tracking is currently set to '{enabled_value}'.{Style.RESET_ALL}")
        print(f"{Fore.GREEN}    [*] Advice: If this device is being used as a transit router, you might consider disabling Connection Tracking to improve performance. However, proceed with caution as it can affect certain network features.{Style.RESET_ALL}")
        print()


def check_romon_enabled(config_data):
    pattern = r"/tool romon\s+set.*enabled=yes"
    match = re.search(pattern, config_data)
    
    if match:
        print(f"{Style.BRIGHT}[+] Checking RoMON Settings{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    [!] Warning: RoMON is enabled. If you are using RoMON, you should carefully manage its settings, as an attacker might use it to gain access to other RouterOS devices.{Style.RESET_ALL}")
        print(f"{Fore.GREEN}    [*] Advice: Regularly review RoMON configurations and ensure that only authorized devices can use RoMON.{Style.RESET_ALL}")
        print()

def check_mac_server_settings(config_data):
    mac_server_pattern = r"/tool mac-server\s+set.*allowed-interface-list=all"
    mac_winbox_pattern = r"/tool mac-server mac-winbox\s+set.*allowed-interface-list=all"
    mac_ping_pattern = r"/tool mac-server ping\s+set.*enabled=yes"
    
    mac_server_match = re.search(mac_server_pattern, config_data)
    mac_winbox_match = re.search(mac_winbox_pattern, config_data)
    mac_ping_match = re.search(mac_ping_pattern, config_data)
    
    if mac_server_match or mac_winbox_match or mac_ping_match:
        print(f"{Style.BRIGHT}[+] Checking MAC Server Settings{Style.RESET_ALL}")
        
        if mac_server_match:
            print(f"{Fore.YELLOW}    [!] Warning: MAC Server is allowed on all interfaces (allowed-interface-list=all). This compromises the security of the Winbox interface.{Style.RESET_ALL}")
        
        if mac_winbox_match:
            print(f"{Fore.YELLOW}    [!] Warning: MAC Winbox is allowed on all interfaces (allowed-interface-list=all). This compromises the security of the Winbox interface.{Style.RESET_ALL}")
        
        if mac_ping_match:
            print(f"{Fore.YELLOW}    [!] Warning: MAC Ping is enabled. Possible unwanted traffic.{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}    [*] Solution: Limit MAC server and MAC Winbox to specific trusted interfaces, and disable MAC Ping if it is not required.{Style.RESET_ALL}")
        print()

def check_snmp_communities(config_data):
    public_pattern = r'/snmp community[\s\S]*?(set|add)[\s\S]*?name=public'
    private_pattern = r'/snmp community[\s\S]*?(set|add)[\s\S]*?name=private'
    
    public_match = re.search(public_pattern, config_data)
    private_match = re.search(private_pattern, config_data)

    if public_match or private_match:
        print(f"{Style.BRIGHT}[+] Checking SNMP Communities{Style.RESET_ALL}")
        
        if public_match:
            print(f"{Fore.YELLOW}    [!] Warning: SNMP community 'public' is in use. Possible Information Gathering attack vector by bruteforcing community string.{Style.RESET_ALL}")
        
        if private_match:
            print(f"{Fore.YELLOW}    [!] Warning: SNMP community 'private' is in use. Possible Information Gathering attack vector by bruteforcing community string.{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}    [*] Solution: Change the SNMP community names to something more secure, and restrict SNMP access to trusted IP addresses only.{Style.RESET_ALL}")
        print()

def check_port_forwarding_rules(config_data):
    nat_pattern = r"add\s+action=dst-nat(?:\s+\S+)*\s+to-addresses=\S+(?:\s+\S+)*\s+to-ports=\S+"
    matches = re.findall(nat_pattern, config_data, re.DOTALL)

    if matches:
        print(f"{Style.BRIGHT}[+] Checking Port Forwarding (dst-nat){Style.RESET_ALL}")
        for match in matches:
            print(f"{Fore.YELLOW}    [!] Warning: Port forwarding detected:{Style.RESET_ALL} {match.strip()}. This may expose your internal network to the internet.")
            print(f"{Fore.CYAN}    [!] Risk: Using port forwarding reduces the level of network security. A device exposed to the internet via port forwarding can be hacked, putting the internal infrastructure at risk.")
            print(f"{Fore.GREEN}    [*] Solution: It's better to avoid port forwarding in favor of VPN servers for accessing the internal infrastructure from outside.{Style.RESET_ALL}")
        print()


def main():
    banner()
    args = parse_arguments()
    config_file = args.config_file
    
    try:
        with open(config_file, 'r') as file:
            config_data = file.read()
            print(f"{Style.BRIGHT}[*] Analyzing the configuration file: {config_file} ({round(len(config_data)/1024, 2)} KB){Style.RESET_ALL}\n")
            extract_device_info(config_data)
            check_smb_enabled(config_data)
            check_rmi_services(config_data)
            check_upnp_enabled(config_data)
            check_wifi_settings(config_data)
            check_dns_settings(config_data)
            check_ddns_enabled(config_data)
            check_poe_settings(config_data)
            check_protected_routerboot(config_data)
            check_socks_enabled(config_data)
            check_bandwidth_server_enabled(config_data)
            check_ospf_interfaces(config_data)
            check_vrrp_interfaces(config_data)
            check_discovery_protocols(config_data)
            check_user_password_policies(config_data)
            check_ssh_strong_crypto(config_data)
            check_connection_tracking(config_data)
            check_romon_enabled(config_data)
            check_mac_server_settings(config_data)
            check_snmp_communities(config_data)
            check_port_forwarding_rules(config_data)
            
    except FileNotFoundError:
        print(f"{Fore.RED}Error: The file '{config_file}' was not found.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error: An unexpected error occurred: {e}{Style.RESET_ALL}")

# Проверка на запуск скрипта
if __name__ == "__main__":
    main()
