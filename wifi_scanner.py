from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp
from tabulate import tabulate
from termcolor import colored
import socket
import nmap

# Define the target network range
network_range = "192.168.1.0/24"  # Adjust to the network range you want to scan

# Create an Nmap scanner
nm = nmap.PortScanner()


def scan(ip_range):
    try:
        # Send an ARP request to all IPs in the subnet to get their MAC addresses
        arp_request = ARP(pdst=ip_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list, _ = srp(arp_request_broadcast, timeout=2, verbose=False)

        # Prepare the results list
        results = []

        # Iterate over the list of IPs that responded
        for _, received in answered_list:
            ip_address = received.psrc
            mac_address = received.hwsrc

            # Perform an Nmap scan with OS detection
            nm.scan(hosts=ip_address, arguments="-O -sV")

            # Check if the host is up and prepare OS information
            if nm.all_hosts() and "up" in nm[ip_address].state():
                os_info = []
                if "osmatch" in nm[ip_address]:
                    for osmatch in nm[ip_address]["osmatch"]:
                        os_info.append(f"{osmatch['name']} ({osmatch['accuracy']}%)")
                else:
                    os_info.append("Not Detected")

                results.append([ip_address, mac_address, "\n".join(os_info)])

        # Print the results in a table
        headers = ["IP Address", "MAC Address", "Possible OS"]
        print(colored(tabulate(results, headers=headers, tablefmt="grid"), "green"))

    except KeyboardInterrupt:
        print(colored("\nScanning stopped by user.", "red"))
    except socket.gaierror:
        print(colored("Hostname could not be resolved.", "red"))
    except Exception as e:
        print(colored(f"An error occurred: {str(e)}", "red"))


# Scan the network
if __name__ == "__main__":
    scan(network_range)
