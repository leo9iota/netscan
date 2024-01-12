from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp
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

        for _, received in answered_list:
            ip_address = received.psrc
            mac_address = received.hwsrc

            print(f"IP Address: {ip_address}, MAC Address: {mac_address}")

            # Perform an Nmap scan with OS detection
            nm.scan(
                hosts=ip_address, arguments="-O -sV"
            )  # -O for OS detection, -sV for service version

            # Check if the host is up and print OS information
            if nm.all_hosts() and "up" in nm[ip_address].state():
                print(f"Host {ip_address} is up.")

                # Print OS details if available
                if "osmatch" in nm[ip_address]:
                    for osmatch in nm[ip_address]["osmatch"]:
                        print(
                            f"Possible OS: {osmatch['name']}, Accuracy: {osmatch['accuracy']}%"
                        )
                        if "osclass" in osmatch:
                            for osclass in osmatch["osclass"]:
                                print(
                                    f"Type: {osclass['type']}, Vendor: {osclass['vendor']}, OS Family: {osclass['osfamily']}, OS Generation: {osclass['osgen']}"
                                )

    except KeyboardInterrupt:
        print("\nScanning stopped by user.")
    except socket.gaierror:
        print("Hostname could not be resolved.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")


# Scan the network
if __name__ == "__main__":
    scan(network_range)
