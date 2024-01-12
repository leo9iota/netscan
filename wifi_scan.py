from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp
import socket
import nmap

# Define the target Wi-Fi network range
wifi_network = "192.168.1.0/24"  # Update this to your office Wi-Fi network range

# Create an Nmap scanner
nm = nmap.PortScanner()


def scan(ip):
    try:
        # Send an ARP request to get the MAC address
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        # Extract MAC addresses and perform an Nmap scan
        for element in answered_list:
            mac_address = element[1].hwsrc
            ip_address = element[1].psrc

            # Perform an Nmap scan to gather more information
            nm.scan(hosts=ip_address, arguments="-O")

            # Retrieve device type from Nmap results
            device_type = (
                nm[ip_address]["osclass"][0]["osfamily"]
                if ip_address in nm.all_hosts()
                else "Unknown"
            )

            # Print the gathered information
            print(
                f"IP Address: {ip_address}, MAC Address: {mac_address}, Device Type: {device_type}"
            )

    except KeyboardInterrupt:
        print("\nScanning stopped by user.")
        exit()
    except socket.gaierror:
        print("Hostname could not be resolved.")
        exit()
    except Exception as e:
        print(f"An error occurred: {str(e)}")


def scan_network(target_network):
    scan(target_network)


if __name__ == "__main__":
    scan_network(wifi_network)
