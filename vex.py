#!/usr/bin/env python3

import argparse
import re
from colorama import init, Fore, Style

init(autoreset=True)

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True, help='RouterOS configuration file name')
    return parser.parse_args()

def load_config(file_path):
    with open(file_path, 'r') as file:
        return file.read().splitlines()

def combine_multiline_statements(config_lines):
    combined_lines = []
    buffer = ""
    for line in config_lines:
        line = line.strip()
        if line.endswith("\\"):
            buffer += line[:-1] + " "
        else:
            buffer += line
            combined_lines.append(buffer)
            buffer = ""
    return combined_lines

def extract_device_info(config_lines):
    software_id = None
    model = None
    serial_number = None
    version = None

    for line in config_lines:
        if line.startswith("# software id ="):
            software_id = line.split('=')[1].strip()
        elif line.startswith("# model ="):
            model = line.split('=')[1].strip()
        elif line.startswith("# serial number ="):
            serial_number = line.split('=')[1].strip()

    return software_id, model, serial_number

def extract_interfaces(config_lines):
    interfaces = []
    current_interface_type = None
    
    for line in config_lines:
        line = line.strip()
        if line.startswith('/interface '):
            current_interface_type = line.split()[1]
            continue

        if line.startswith('/') and not line.startswith('/interface'):
            current_interface_type = None

        if current_interface_type:
            if line.startswith('set ') or line.startswith('add '):
                name_match = re.search(r'name=(\S+)', line)
                default_name_match = re.search(r'default-name=(\S+)', line)
                if name_match:
                    interface_name = name_match.group(1)
                    interfaces.append((current_interface_type, interface_name))
                elif default_name_match:
                    interface_name = default_name_match.group(1)
                    interfaces.append((current_interface_type, interface_name))
    
    return interfaces

def extract_ip_addresses(config_lines):
    ip_addresses = []
    ip_pattern = re.compile(r'^/ip address')
    add_pattern = re.compile(r'add address=([\d\.\/]+)(?: disabled=\S+)? interface=(\S+) network=\S+')

    inside_ip_address_block = False
    
    for line in config_lines:
        if ip_pattern.match(line):
            inside_ip_address_block = True
            continue
        
        if inside_ip_address_block and line.startswith("add "):
            add_match = add_pattern.search(line)
            if add_match:
                ip_address = add_match.group(1)
                interface_name = add_match.group(2)
                ip_addresses.append((ip_address, interface_name))

    return ip_addresses

def check_discovery_protocols(config_lines):
    discovery_pattern = re.compile(r'^/ip neighbor discovery-settings')
    set_pattern = re.compile(r'set discover-interface-list=(\S+)')
    
    for line in config_lines:
        if discovery_pattern.match(line):
            next_line_index = config_lines.index(line) + 1
            if next_line_index < len(config_lines):
                next_line = config_lines[next_line_index]
                set_match = set_pattern.search(next_line)
                if set_match:
                    discovery_setting = set_match.group(1)
                    if discovery_setting.lower() == 'all':
                        return (True, f"detected set discover-interface-list={discovery_setting}")
    return (False, "No security issues found with Discovery protocols.")

def check_bandwidth_server(config_lines):
    bandwidth_pattern = re.compile(r'^/tool bandwidth-server')
    set_pattern_enabled = re.compile(r'set .*enabled=yes')
    set_pattern_disabled = re.compile(r'set .*enabled=no')

    inside_bandwidth_block = False
    for line in config_lines:
        if bandwidth_pattern.match(line):
            inside_bandwidth_block = True
            continue
        
        if inside_bandwidth_block:
            if set_pattern_disabled.search(line):
                return (False, "No issues found with Bandwidth Server.")
            elif set_pattern_enabled.search(line):
                return (True, "detected active Bandwidth Server with 'enabled=yes' setting")
    
    return (True, "detected active Bandwidth Server (default enabled)")

def check_dns_settings(config_lines):
    dns_pattern = re.compile(r'^/ip dns')
    set_pattern = re.compile(r'set allow-remote-requests=yes')
    
    for line in config_lines:
        if dns_pattern.match(line):
            next_line_index = config_lines.index(line) + 1
            if next_line_index < len(config_lines):
                next_line = config_lines[next_line_index]
                if set_pattern.search(next_line):
                    return (True, "detected directive 'set allow-remote-requests=yes'")
    return (False, "No issues found with DNS settings.")

def check_ddns(config_lines):
    ddns_pattern = re.compile(r'^/ip cloud')
    set_pattern = re.compile(r'set ddns-enabled=yes')
    
    for line in config_lines:
        if ddns_pattern.match(line):
            next_line_index = config_lines.index(line) + 1
            if next_line_index < len(config_lines):
                next_line = config_lines[next_line_index]
                if set_pattern.search(next_line):
                    return (True, "DDNS is enabled. If not specifically used, it is recommended to disable it.")
    return (False, "No issues found with DDNS settings.")

def check_upnp_settings(config_lines):
    upnp_pattern = re.compile(r'^/ip upnp')
    set_pattern = re.compile(r'set .*enabled=(yes|no)')
    
    inside_upnp_block = False
    
    for line in config_lines:
        if upnp_pattern.match(line):
            inside_upnp_block = True
            continue
        
        if inside_upnp_block:
            set_match = set_pattern.search(line)
            if set_match:
                upnp_status = set_match.group(1)
                if upnp_status == "yes":
                    return (True, "detected directive 'set enabled=yes'")
            inside_upnp_block = False
            
    return (False, "No issues found with UPnP settings.")

def extract_firewall_rules(config_lines, table):
    firewall_rules = []
    firewall_pattern = re.compile(rf'^/ip firewall {table}')
    add_pattern = re.compile(r'add .*')

    inside_firewall_block = False
    
    for line in config_lines:
        if firewall_pattern.match(line):
            inside_firewall_block = True
            continue
        
        if inside_firewall_block:
            if line.startswith("add "):
                firewall_rules.append(line)
            else:
                inside_firewall_block = False
                
    return firewall_rules

def extract_nat_rules(config_lines):
    nat_rules = []
    nat_pattern = re.compile(r'^/ip firewall nat')
    add_pattern = re.compile(r'add .*')

    inside_nat_block = False
    
    for line in config_lines:
        if nat_pattern.match(line):
            inside_nat_block = True
            continue
        
        if inside_nat_block:
            if line.startswith("add "):
                nat_rules.append(line)
            else:
                inside_nat_block = False
                
    return nat_rules

def check_bpdu_guard(config_lines):
    bridge_port_pattern = re.compile(r'^/interface bridge port')
    bpdu_guard_pattern = re.compile(r'add .*bpdu-guard=no')
    
    for line in config_lines:
        if bridge_port_pattern.match(line):
            next_line_index = config_lines.index(line) + 1
            while next_line_index < len(config_lines) and config_lines[next_line_index].startswith('add '):
                if bpdu_guard_pattern.search(config_lines[next_line_index]):
                    return (True, "detected 'bpdu-guard=no'. It is recommended to enable BPDU Guard to protect STP from attacks")
                next_line_index += 1
    return (False, "No issues found with BPDU Guard settings.")

def check_ssh_settings(config_lines):
    ssh_pattern = re.compile(r'^/ip ssh')
    strong_crypto_pattern = re.compile(r'set .*strong-crypto=no')
    
    for line in config_lines:
        if ssh_pattern.match(line):
            next_line_index = config_lines.index(line) + 1
            if next_line_index < len(config_lines):
                next_line = config_lines[next_line_index]
                if strong_crypto_pattern.search(next_line):
                    return (True, "detected 'strong-crypto=no'. It is recommended to enable strong cryptographic ciphers for SSH")
    return (False, "No issues found with SSH settings.")


def check_dhcp_snooping(config_lines):
    bridge_pattern = re.compile(r'^/interface bridge')
    dhcp_snooping_pattern = re.compile(r'add .*dhcp-snooping=no')
    
    for line in config_lines:
        if bridge_pattern.match(line):
            next_line_index = config_lines.index(line) + 1
            while next_line_index < len(config_lines) and config_lines[next_line_index].startswith('add '):
                if dhcp_snooping_pattern.search(config_lines[next_line_index]):
                    return (True, "detected 'dhcp-snooping=no'. It is recommended to enable DHCP Snooping to protect the network from DHCP attacks (DHCP Spoofing)")
                next_line_index += 1
    return (False, "No issues found with DHCP Snooping settings.")

def extract_routes(config_lines):
    routes = []
    route_pattern = re.compile(r'^/ip route')
    add_pattern = re.compile(r'add .*')

    inside_route_block = False
    
    for line in config_lines:
        if route_pattern.match(line):
            inside_route_block = True
            continue
        
        if inside_route_block:
            if line.startswith("add "):
                routes.append(line)
            else:
                inside_route_block = False
                
    return routes

def check_socks_settings(config_lines):
    socks_pattern = re.compile(r'^/ip socks')
    set_pattern = re.compile(r'set .*enabled=yes')
    
    for line in config_lines:
        if socks_pattern.match(line):
            next_line_index = config_lines.index(line) + 1
            if next_line_index < len(config_lines):
                next_line = config_lines[next_line_index]
                if set_pattern.search(next_line):
                    return (True, "detected directive 'set enabled=yes'. SOCKS proxy can be used as a pivoting tool to access the internal network")
    return (False, "No issues found with SOCKS settings.")

def check_vrrp_authentication(config_lines):
    vrrp_pattern = re.compile(r'^/interface vrrp')
    auth_pattern = re.compile(r'authentication=none')
    
    for line in config_lines:
        if vrrp_pattern.match(line):
            next_line_index = config_lines.index(line) + 1
            if next_line_index < len(config_lines):
                next_line = config_lines[next_line_index]
                if auth_pattern.search(next_line):
                    return (True, "VRRP authentication is set to 'none'. This poses a risk of VRRP Hijacking.", "It's recommended to set the maximum priority to 255 if possible. If using VRRPv3, use FW to filter traffic towards MCAST 224.0.0.18")
    return (False, "No issues found with VRRP authentication settings", None)

def check_ospf_authentication(config_lines):
    ospf_pattern = re.compile(r'^/routing ospf interface-template')
    auth_pattern = re.compile(r'auth=')
    
    inside_ospf_block = False
    
    for line in config_lines:
        if ospf_pattern.match(line):
            inside_ospf_block = True
            continue
        
        if inside_ospf_block:
            if 'add ' in line:
                if auth_pattern.search(line) is None:
                    return (True, "OSPF authentication is not configured. This poses a security risk.")
                inside_ospf_block = False
                
    return (False, "No issues found with OSPF authentication settings.")

def check_ospf_passive_setting(config_lines):
    ospf_pattern = re.compile(r'^/routing ospf interface-template')
    auth_pattern = re.compile(r'auth=')
    passive_pattern = re.compile(r'passive')

    inside_ospf_block = False
    auth_missing = False
    passive_missing = False

    for line in config_lines:
        if ospf_pattern.match(line):
            inside_ospf_block = True
            continue
        
        if inside_ospf_block:
            if 'add ' in line:
                if auth_pattern.search(line) is None:
                    auth_missing = True
                if passive_pattern.search(line) is None:
                    passive_missing = True
                inside_ospf_block = False

    return auth_missing, passive_missing

def check_ip_services(config_lines):
    services_pattern = re.compile(r'^/ip service')
    telnet_pattern = re.compile(r'set telnet .*disabled=(yes|no)')
    ftp_pattern = re.compile(r'set ftp .*disabled=(yes|no)')
    api_pattern = re.compile(r'set api .*disabled=(yes|no)')
    api_ssl_pattern = re.compile(r'set api-ssl .*disabled=(yes|no)')
    ssh_pattern = re.compile(r'set ssh .*disabled=(yes|no)')
    winbox_pattern = re.compile(r'set winbox .*disabled=(yes|no)')
    www_pattern = re.compile(r'set www .*disabled=(yes|no)')
    www_ssl_pattern = re.compile(r'set www-ssl .*disabled=(yes|no)')
    
    warnings = set()
    info = set()
    
    inside_services_block = False
    
    for line in config_lines:
        if services_pattern.match(line):
            inside_services_block = True
            continue
        
        if inside_services_block:
            if telnet_pattern.search(line):
                telnet_disabled = telnet_pattern.search(line).group(1)
                if telnet_disabled == "no":
                    warnings.add((True, "Telnet service is enabled. Turn it off, it's not safe to operate the equipment with it"))
                else:
                    info.add((False, Fore.YELLOW + Style.BRIGHT + "Telnet service is " + Fore.WHITE + Style.BRIGHT + "disabled"))
            if ftp_pattern.search(line):
                ftp_disabled = ftp_pattern.search(line).group(1)
                if ftp_disabled == "no":
                    warnings.add((True, "FTP service is enabled. If you don't use FTP, disable it and try not to store sensitive information there"))
                else:
                    info.add((False, Fore.YELLOW + Style.BRIGHT + "FTP service is " + Fore.WHITE + Style.BRIGHT + "disabled"))
            if api_pattern.search(line):
                api_disabled = api_pattern.search(line).group(1)
                if api_disabled == "no":
                    warnings.add((True, "API service is enabled. If not in use, it is recommended to disable it to prevent brute-force attacks"))
                else:
                    info.add((False, Fore.YELLOW + Style.BRIGHT + "API service is " + Fore.WHITE + Style.BRIGHT + "disabled"))
            if api_ssl_pattern.search(line):
                api_ssl_disabled = api_ssl_pattern.search(line).group(1)
                if api_ssl_disabled == "no":
                    warnings.add((True, "API-SSL service is enabled. If not in use, it is recommended to disable it to prevent brute-force attacks"))
                else:
                    info.add((False, Fore.YELLOW + Style.BRIGHT + "API-SSL service is " + Fore.WHITE + Style.BRIGHT + "disabled"))
            if ssh_pattern.search(line):
                ssh_disabled = ssh_pattern.search(line).group(1)
                if ssh_disabled == "no":
                    warnings.add((True, "SSH service is enabled. Filter access, you can use more secure key authentication"))
                else:
                    info.add((False, Fore.YELLOW + Style.BRIGHT + "SSH service is " + Fore.WHITE + Style.BRIGHT + "disabled"))
            if winbox_pattern.search(line):
                winbox_disabled = winbox_pattern.search(line).group(1)
                if winbox_disabled == "no":
                    warnings.add((True, "Winbox service is enabled. Winbox is constantly being attacked. Be careful with it, filter access"))
                else:
                    info.add((False, Fore.YELLOW + Style.BRIGHT + "Winbox service is " + Fore.WHITE + Style.BRIGHT + "disabled"))
            if www_pattern.search(line):
                www_disabled = www_pattern.search(line).group(1)
                if www_disabled == "no":
                    warnings.add((True, "HTTP service is enabled. Be careful with web-based control panels. Filter access"))
                else:
                    info.add((False, Fore.YELLOW + Style.BRIGHT + "HTTP service is " + Fore.WHITE + Style.BRIGHT + "disabled"))
            if www_ssl_pattern.search(line):
                www_ssl_disabled = www_ssl_pattern.search(line).group(1)
                if www_ssl_disabled == "no":
                    warnings.add((True, "HTTPS service is enabled. Be careful with web-based control panels. Filter access"))
                else:
                    info.add((False, Fore.YELLOW + Style.BRIGHT + "HTTPS service is " + Fore.WHITE + Style.BRIGHT + "disabled"))
    
    return list(warnings), list(info)

def check_ntp_client(config_lines):
    ntp_client_pattern = re.compile(r'^/system ntp client')
    set_pattern = re.compile(r'set enabled=yes mode=unicast servers=(\S+)')

    ntp_client_enabled = False
    ntp_servers = []

    for line in config_lines:
        if ntp_client_pattern.match(line):
            next_line_index = config_lines.index(line) + 1
            if next_line_index < len(config_lines):
                next_line = config_lines[next_line_index]
                set_match = set_pattern.search(next_line)
                if set_match:
                    ntp_client_enabled = True
                    ntp_servers = set_match.group(1).split(',')

    if ntp_client_enabled:
        return (True, f"NTP client is enabled. Servers: {', '.join(ntp_servers)}")
    else:
        return (False, "NTP client is not enabled or not using unicast mode.")

def check_romon_settings(config_lines):
    romon_pattern = re.compile(r'^/tool romon')
    set_pattern = re.compile(r'set .*enabled=yes')

    inside_romon_block = False

    for line in config_lines:
        if romon_pattern.match(line):
            inside_romon_block = True
            continue
        
        if inside_romon_block:
            if set_pattern.search(line):
                return (True, "ROMON is enabled. Be careful with this. If RouterOS is compromised, ROMON can be jumped to the next MikroTik hardware")
            inside_romon_block = False
    
    return (False, "No issues found with ROMON settings.")

def check_mac_telnet_server(config_lines):
    mac_server_pattern = re.compile(r'^/tool mac-server')
    allowed_interface_list_pattern = re.compile(r'set allowed-interface-list=all')

    inside_mac_server_block = False
    
    for line in config_lines:
        if mac_server_pattern.match(line):
            inside_mac_server_block = True
            continue
        
        if inside_mac_server_block:
            if allowed_interface_list_pattern.search(line):
                return (True, "MAC Telnet server is active on all interfaces. This reduces the security of the Winbox interface. Filter access")
            inside_mac_server_block = False
    
    return (False, "No issues found with MAC Telnet Server settings.")

def check_mac_winbox_server(config_lines):
    mac_winbox_pattern = re.compile(r'^/tool mac-server mac-winbox')
    inside_mac_winbox_block = False

    for line in config_lines:
        if mac_winbox_pattern.match(line):
            inside_mac_winbox_block = True
            continue
        
        if inside_mac_winbox_block:
            if 'set allowed-interface-list=all' in line:
                return (True, "MAC Winbox Server is accessible on all interfaces. This reduces the security of the Winbox interface. Filter access")
            inside_mac_winbox_block = False
    
    return (False, "No issues found with MAC Winbox Server settings.")

def check_mac_ping_server(config_lines):
    mac_ping_pattern = re.compile(r'^/tool mac-server ping')
    inside_mac_ping_block = False

    for line in config_lines:
        if mac_ping_pattern.match(line):
            inside_mac_ping_block = True
            continue
        
        if inside_mac_ping_block:
            if 'set enabled=yes' in line:
                return (True, "MAC Ping Server is enabled. Possible unwanted traffic")
            inside_mac_ping_block = False
    
    return (False, "No issues found with MAC Ping Server settings.")

def check_snmp_communities(config_lines):
    snmp_pattern = re.compile(r'^/snmp community')
    name_pattern = re.compile(r'name=(\S+)')
    
    issues_found = False
    snmp_issues = []

    inside_snmp_block = False

    for line in config_lines:
        if snmp_pattern.match(line):
            inside_snmp_block = True
            continue
        
        if inside_snmp_block:
            name_match = name_pattern.search(line)
            if name_match:
                snmp_name = name_match.group(1)
                if snmp_name.lower() in ["public", "private"]:
                    issues_found = True
                    snmp_issues.append(f"SNMP community '{snmp_name}' is set. Information Disclosure is possible. Please change SNMP community string")
                    
    if issues_found:
        return (True, snmp_issues)
    else:
        return (False, "No issues found with SNMP settings.")

if __name__ == "__main__":
    banner = '''
    VVVVVVVV           VVVVVVVV                                
    V::::::V           V::::::V                                
    V::::::V           V::::::V                                
    V::::::V           V::::::V                                
     V:::::V           V:::::Veeeeeeeeeeee xxxxxxx      xxxxxxx
      V:::::V         V:::::ee::::::::::::eex:::::x    x:::::x 
       V:::::V       V:::::e::::::eeeee:::::ex:::::x  x:::::x  
        V:::::V     V:::::e::::::e     e:::::ex:::::xx:::::x   
         V:::::V   V:::::Ve:::::::eeeee::::::e x::::::::::x    
          V:::::V V:::::V e:::::::::::::::::e   x::::::::x     
           V:::::V:::::V  e::::::eeeeeeeeeee    x::::::::x     
            V:::::::::V   e:::::::e            x::::::::::x    
             V:::::::V    e::::::::e          x:::::xx:::::x   
              V:::::V      e::::::::eeeeeeee x:::::x  x:::::x  
               V:::V        ee:::::::::::::ex:::::x    x:::::x 
                VVV           eeeeeeeeeeeeexxxxxxx      xxxxxxx                                                  
'''

    print(banner)
    print("    Vex: RouterOS Security Inspector")
    print("    Designed for security engineers\n")
    print("    For documentation visit: https://github.com/casterbyte/Vex\n")
    print("    " + Fore.YELLOW + "Author: " + Style.RESET_ALL + "Magama Bazarov, <caster@exploit.org>")
    print("    " + Fore.YELLOW + "Pseudonym: " + Style.RESET_ALL + "Caster")
    print("    " + Fore.YELLOW + "Version: " + Style.RESET_ALL + "1.0\n")
    print("    " + Fore.YELLOW + Style.BRIGHT + "DISCLAIMER: The tool is intended solely for analyzing the security of RouterOS hardware. The author is not responsible for any damage caused by using this tool")
    print("    " + Fore.YELLOW + Style.BRIGHT + "CAUTION: for the tool to work correctly, use the RouterOS configuration from using the" + Fore.WHITE + Style.BRIGHT + " export verbose command\n")


    args = parse_arguments()
    config_lines = load_config(args.config)
    config_lines = combine_multiline_statements(config_lines)
    
    software_id, model, serial_number = extract_device_info(config_lines)
    print(Fore.WHITE + Style.BRIGHT + "[+] Device Information:" + Style.RESET_ALL)
    if software_id:
        print(Fore.YELLOW + Style.BRIGHT + "[*] Software ID: " + Fore.WHITE + Style.BRIGHT + f"{software_id}")
    else:
        print(Fore.YELLOW + Style.BRIGHT + "[*] Software ID: " + Fore.WHITE + Style.BRIGHT + "unknown")
    if model:
        print(Fore.YELLOW + Style.BRIGHT + "[*] Model: " + Fore.WHITE + Style.BRIGHT + f"{model}")
    else:
        print(Fore.YELLOW + Style.BRIGHT + "[*] Model: " + Fore.WHITE + Style.BRIGHT + "unknown")
    if serial_number:
        print(Fore.YELLOW + Style.BRIGHT + "[*] Serial Number: " + Fore.WHITE + Style.BRIGHT + f"{serial_number}")
    else:
        print(Fore.YELLOW + Style.BRIGHT + "[*] Serial Number: " + Fore.WHITE + Style.BRIGHT + "unknown")
    print("------------------------------")
    
    interfaces = extract_interfaces(config_lines)
    print(Fore.WHITE + Style.BRIGHT + "[+] Interfaces found:" + Style.RESET_ALL)
    if interfaces:
        for interface_type, interface_name in interfaces:
            print(Fore.YELLOW + Style.BRIGHT + "[*] Type: " + Fore.WHITE + Style.BRIGHT + f"{interface_type}, " + Fore.YELLOW + Style.BRIGHT + "Name: " + Fore.WHITE + Style.BRIGHT + f"{interface_name}")
    else:
        print(Fore.YELLOW + Style.BRIGHT + "[*] No interfaces found.")
    print("------------------------------")
    
    ip_addresses = extract_ip_addresses(config_lines)
    print(Fore.WHITE + Style.BRIGHT + "[+] IP Addresses found:" + Style.RESET_ALL)
    if ip_addresses:
        for ip_address, interface_name in ip_addresses:
            print(Fore.YELLOW + Style.BRIGHT + "[*] IP Address: " + Fore.WHITE + Style.BRIGHT + f"{ip_address}, " + Fore.YELLOW + Style.BRIGHT + "Interface: " + Fore.WHITE + Style.BRIGHT + f"{interface_name}")
    else:
        print(Fore.YELLOW + Style.BRIGHT + "[*] No IP addresses found.")
    print("------------------------------")
    
    discovery_protocol_status, discovery_protocol_message = check_discovery_protocols(config_lines)
    print(Fore.GREEN + Style.BRIGHT + "[+] Discovery Protocols Check:" + Style.RESET_ALL)
    if discovery_protocol_status:
        print(Fore.RED + Style.BRIGHT + f"[*] Security Warning: " + Fore.WHITE + Style.BRIGHT + f"{discovery_protocol_message}. Possible disclosure of sensitive information")
    else:
        print(f"[*] {discovery_protocol_message}")
    print("------------------------------")

    bandwidth_server_status, bandwidth_server_message = check_bandwidth_server(config_lines)
    print(Fore.GREEN + Style.BRIGHT + "[+] Bandwidth Server Check:" + Style.RESET_ALL)
    if bandwidth_server_status:
        print(Fore.RED + Style.BRIGHT + f"[*] Security Warning: " + Fore.WHITE + Style.BRIGHT + f"{bandwidth_server_message}. Possible unwanted traffic towards Bandwidth Server, be careful")
    else:
        print(f"[*] {bandwidth_server_message}")
    print("------------------------------")

    dns_settings_status, dns_settings_message = check_dns_settings(config_lines)
    print(Fore.GREEN + Style.BRIGHT + "[+] DNS Settings Check:" + Style.RESET_ALL)
    if dns_settings_status:
        print(Fore.RED + Style.BRIGHT + f"[*] Security Warning: " + Fore.WHITE + Style.BRIGHT + f"{dns_settings_message}. This router is a DNS server, be careful")
        print(Fore.YELLOW + Style.BRIGHT + "[*] Router is acting as a DNS server and should restrict DNS traffic from external sources to prevent DNS Flood attacks")
    else:
        print(f"[*] {dns_settings_message}")
    print("------------------------------")

    ddns_status, ddns_message = check_ddns(config_lines)
    print(Fore.GREEN + Style.BRIGHT + "[+] DDNS Settings Check:" + Style.RESET_ALL)
    if ddns_status:
        print(Fore.YELLOW + Style.BRIGHT + f"[*] Warning: " + Fore.WHITE + Style.BRIGHT + f"{ddns_message}")
    else:
        print(f"[*] {ddns_message}")
    print("------------------------------")

    upnp_settings_status, upnp_settings_message = check_upnp_settings(config_lines)
    print(Fore.GREEN + Style.BRIGHT + "[+] UPnP Settings Check:" + Style.RESET_ALL)
    if upnp_settings_status:
        print(Fore.RED + Style.BRIGHT + f"[*] Security Warning: " + Fore.WHITE + Style.BRIGHT + f"{upnp_settings_message}. The presence of active UPnP can be indicative of post-exploitation of a compromised RouterOS, and it can also be the cause of an external perimeter breach. Switch it off")
    else:
        print(f"[*] {upnp_settings_message}")
    print("------------------------------")

    ssh_status, ssh_message = check_ssh_settings(config_lines)
    print(Fore.GREEN + Style.BRIGHT + "[+] SSH Settings Check:" + Style.RESET_ALL)
    if ssh_status:
        print(Fore.RED + Style.BRIGHT + f"[*] Security Warning: " + Fore.WHITE + Style.BRIGHT + f"{ssh_message}")
    else:
        print(f"[*] {ssh_message}")
    print("------------------------------")

    filter_rules = extract_firewall_rules(config_lines, 'filter')
    print(Fore.GREEN + Style.BRIGHT + "[+] Firewall Filter Rules found:" + Style.RESET_ALL)
    if filter_rules:
        for rule in filter_rules:
            print(Fore.YELLOW + Style.BRIGHT + "[*] Rule:" + Fore.WHITE + Style.BRIGHT + f" {rule}")
    else:
        print(Fore.YELLOW + Style.BRIGHT + "[*] No filter rules found.")
    print(Style.BRIGHT + Fore.YELLOW + "[!] Don't forget to use the 'Drop All Other' rule on the external interface of the router. This helps protect the router from external perimeter breaches.")
    print("------------------------------")

    mangle_rules = extract_firewall_rules(config_lines, 'mangle')
    print(Fore.GREEN + Style.BRIGHT + "[+] Firewall Mangle Rules found:" + Style.RESET_ALL)
    if mangle_rules:
        for rule in mangle_rules:
            print(Fore.YELLOW + Style.BRIGHT + "[*] Rule:" + Fore.WHITE + Style.BRIGHT + f" {rule}")
    else:
        print(Fore.YELLOW + Style.BRIGHT + "[*] No mangle rules found.")
    print(Style.BRIGHT + Fore.YELLOW + "[!] In some scenarios, using the mangle table can help save CPU resources.")
    print("------------------------------")

    nat_rules = extract_nat_rules(config_lines)
    print(Fore.GREEN + Style.BRIGHT + "[+] Firewall NAT Rules found:" + Style.RESET_ALL)
    if nat_rules:
        for rule in nat_rules:
            print(Fore.YELLOW + Style.BRIGHT + "[*] Rule:" + Fore.WHITE + Style.BRIGHT + f" {rule}")
    else:
        print(Fore.YELLOW + Style.BRIGHT + "[*] No NAT rules found.")
    print("------------------------------")

    raw_rules = extract_firewall_rules(config_lines, 'raw')
    print(Fore.GREEN + Style.BRIGHT + "[+] Firewall Raw Rules found:" + Style.RESET_ALL)
    if raw_rules:
        for rule in raw_rules:
            print(Fore.YELLOW + Style.BRIGHT + "[*] Rule:" + Fore.WHITE + Style.BRIGHT + f" {rule}")
    else:
        print(Fore.YELLOW + Style.BRIGHT + "[*] No raw rules found.")
    print("------------------------------")

    routes = extract_routes(config_lines)
    print(Fore.GREEN + Style.BRIGHT + "[+] Routes:" + Style.RESET_ALL)
    if routes:
        for route in routes:
            print(Fore.YELLOW + Style.BRIGHT + f"[*] Route:" + Fore.WHITE + Style.BRIGHT + f" {route}")
    else:
        print(Fore.YELLOW + Style.BRIGHT + "[*] No routes found.")
    print("------------------------------")
    
    socks_status, socks_message = check_socks_settings(config_lines)
    print(Fore.GREEN + Style.BRIGHT + "[+] SOCKS Settings Check:" + Style.RESET_ALL)
    if socks_status:
        print(Fore.RED + Style.BRIGHT + f"[*] Security Warning: " + Fore.WHITE + Style.BRIGHT + f"{socks_message}")
    else:
        print(f"[*] {socks_message}")
    print("------------------------------")
    
    ip_services_warnings, ip_services_info = check_ip_services(config_lines)
    print(Fore.GREEN + Style.BRIGHT + "[+] IP Services Check:" + Style.RESET_ALL)
    if ip_services_warnings:
        for status, message in ip_services_warnings:
            if status:
                print(Fore.RED + Style.BRIGHT + f"[*] Security Warning: " + Fore.WHITE + Style.BRIGHT + f"{message}")
    if ip_services_info:
        for status, message in ip_services_info:
            if not status:
                print(Fore.YELLOW + Style.BRIGHT + f"[*] " + message)
    print("------------------------------")

    bpdu_guard_status, bpdu_guard_message = check_bpdu_guard(config_lines)
    print(Fore.GREEN + Style.BRIGHT + "[+] BPDU Guard Settings Check:" + Style.RESET_ALL)
    if bpdu_guard_status:
        print(Fore.RED + Style.BRIGHT + f"[*] Security Warning: " + Fore.WHITE + Style.BRIGHT + f"{bpdu_guard_message}")
    else:
        print(f"[*] {bpdu_guard_message}")
    print("------------------------------")

    romon_status, romon_message = check_romon_settings(config_lines)
    print(Fore.GREEN + Style.BRIGHT + "[+] ROMON Settings Check:" + Style.RESET_ALL)
    if romon_status:
        print(Fore.RED + Style.BRIGHT + f"[*] Security Warning: " + Fore.WHITE + Style.BRIGHT + f"{romon_message}")
    else:
        print(f"[*] {romon_message}")
    print("------------------------------")

    mac_telnet_status, mac_telnet_message = check_mac_telnet_server(config_lines)
    print(Fore.GREEN + Style.BRIGHT + "[+] MAC Telnet Server Check:" + Style.RESET_ALL)
    if mac_telnet_status:
        print(Fore.RED + Style.BRIGHT + f"[*] Security Warning: " + Fore.WHITE + Style.BRIGHT + f"{mac_telnet_message}")
    else:
        print(f"[*] {mac_telnet_message}")
    print("------------------------------")

    mac_winbox_status, mac_winbox_message = check_mac_winbox_server(config_lines)
    print(Fore.GREEN + Style.BRIGHT + "[+] MAC Winbox Server Check:" + Style.RESET_ALL)
    if mac_winbox_status:
        print(Fore.RED + Style.BRIGHT + f"[*] Security Warning: " + Fore.WHITE + Style.BRIGHT + f"{mac_winbox_message}")
    else:
        print(f"[*] {mac_winbox_message}")
    print("------------------------------")

    mac_ping_status, mac_ping_message = check_mac_ping_server(config_lines)
    print(Fore.GREEN + Style.BRIGHT + "[+] MAC Ping Server Check:" + Style.RESET_ALL)
    if mac_ping_status:
        print(Fore.RED + Style.BRIGHT + f"[*] Security Warning: " + Fore.WHITE + Style.BRIGHT + f"{mac_ping_message}")
    else:
        print(f"[*] {mac_ping_message}")
    print("------------------------------")

    dhcp_snooping_status, dhcp_snooping_message = check_dhcp_snooping(config_lines)
    print(Fore.GREEN + Style.BRIGHT + "[+] DHCP Snooping Settings Check:" + Style.RESET_ALL)
    if dhcp_snooping_status:
        print(Fore.RED + Style.BRIGHT + f"[*] Security Warning: " + Fore.WHITE + Style.BRIGHT + f"{dhcp_snooping_message}")
    else:
        print(f"[*] {dhcp_snooping_message}")
    print("------------------------------")

    ntp_client_status, ntp_client_message = check_ntp_client(config_lines)
    print(Fore.GREEN + Style.BRIGHT + "[+] NTP Client Settings Check:" + Style.RESET_ALL)
    if ntp_client_status:
        print(Fore.YELLOW + Style.BRIGHT + f"[*] Security Warning: " + Fore.WHITE + Style.BRIGHT + f"{ntp_client_message}")
    else:
        print(f"[*] {ntp_client_message}")
    print("------------------------------")

    vrrp_auth_status, vrrp_auth_message, vrrp_auth_advice = check_vrrp_authentication(config_lines)
    print(Fore.GREEN + Style.BRIGHT + "[+] VRRP Security Check:" + Style.RESET_ALL)
    if vrrp_auth_status:
        print(Fore.RED + Style.BRIGHT + f"[*] Security Warning: " + Fore.WHITE + Style.BRIGHT + f"{vrrp_auth_message}")
        if vrrp_auth_advice:
            print(Fore.YELLOW + Style.BRIGHT + f"[!] Advice: {vrrp_auth_advice}")
    else:
        print(f"[*] {vrrp_auth_message}")
    print("------------------------------")

    ospf_auth_status, ospf_passive_status = check_ospf_passive_setting(config_lines)
    print(Fore.GREEN + Style.BRIGHT + "[+] OSPF Security Check:" + Style.RESET_ALL)
    if ospf_auth_status:
        print(Fore.RED + Style.BRIGHT + f"[*] Security Warning: " + Fore.WHITE + Style.BRIGHT + "OSPF authentication is not configured. There is a risk of connecting an illegal OSPF speaker")
    if ospf_passive_status:
        print(Fore.RED + Style.BRIGHT + f"[*] Security Warning: " + Fore.WHITE + Style.BRIGHT + "OSPF passive interfaces are not configured. There is a risk of connecting an illegal OSPF speaker")
    if not ospf_auth_status and not ospf_passive_status:
        print(f"[*] No issues found with OSPF settings.")
    print("------------------------------")

    snmp_status, snmp_message = check_snmp_communities(config_lines)
    print(Fore.GREEN + Style.BRIGHT + "[+] SNMP Security Check:" + Style.RESET_ALL)
    if snmp_status:
        for message in snmp_message:
            print(Fore.RED + Style.BRIGHT + f"[*] Security Warning: " + Fore.WHITE + Style.BRIGHT + f"{message}")
    else:
        print(f"[*] {snmp_message}")
    print("------------------------------")

# end of code