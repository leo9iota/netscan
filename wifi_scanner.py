from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp
from tabulate import tabulate
from termcolor import colored
import socket
import nmap
import threading

# Define the target network range
network_range = "192.168.1.0/24"  # Adjust to the network range you want to scan

# Create an Nmap scanner
nm = nmap.PortScanner()

# Results list and a lock for thread-safe operations
results = []
print_lock = threading.Lock()


def scan_host(ip_address):
    try:
        # Perform an Nmap scan with OS detection on a single host
        nm.scan(hosts=ip_address, arguments="-O -sV")

        # Check if the host is up and prepare OS information
        if "up" == nm[ip_address].state():
            os_info = []
            if "osmatch" in nm[ip_address]:
                for osmatch in nm[ip_address]["osmatch"]:
                    os_info.append(f"{osmatch['name']} ({osmatch['accuracy']}%)")
            else:
                os_info.append("Not Detected")

            # Append results
            with print_lock:
                results.append(
                    [
                        ip_address,
                        nm[ip_address]["addresses"].get("mac", "Not Detected"),
                        "\n".join(os_info),
                    ]
                )

    except Exception as e:
        with print_lock:
            print(
                colored(
                    f"An error occurred while scanning {ip_address}: {str(e)}", "red"
                )
            )


def initial_scan(ip_range):
    try:
        # Send an ARP request to all IPs in the subnet to get their MAC addresses
        arp_request = ARP(pdst=ip_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list, _ = srp(
            arp_request_broadcast, timeout=1, verbose=False
        )  # Reduced timeout for local network

        # List to hold all the thread objects
        threads = []

        # Iterate over the list of IPs that responded
        for _, received in answered_list:
            ip_address = received.psrc

            # Spawn a new thread for each host scan
            thread = threading.Thread(target=scan_host, args=(ip_address,))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

    except KeyboardInterrupt:
        print(colored("\nScanning stopped by user.", "red"))
    except socket.gaierror:
        print(colored("Hostname could not be resolved.", "red"))
    except Exception as e:
        print(colored(f"An error occurred during the initial scan: {str(e)}", "red"))


# Scan the network
if __name__ == "__main__":
    initial_scan(network_range)

    # Print the results in a table
    headers = ["IP Address", "MAC Address", "Possible OS"]
    print(colored(tabulate(results, headers=headers, tablefmt="grid"), "green"))
