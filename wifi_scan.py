from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp
import socket
import nmap

# Define the target IP address (for a single host)
target_ip = "192.168.1.222"  # The specific IP address you want to scan

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
            host_ip = element[1].psrc  # Renamed to avoid shadowing

            # Perform an Nmap scan to gather more information
            nm.scan(hosts=host_ip, arguments="-O")

            # Check if 'osclass' information is available in the Nmap results
            if "osclass" in nm[host_ip]:
                device_type = (
                    nm[host_ip]["osclass"][0]["osfamily"]
                    if "osfamily" in nm[host_ip]["osclass"][0]
                    else "Unknown"
                )
            else:
                device_type = "Unknown"

            # Print the gathered information
            print(
                f"IP Address: {host_ip}, MAC Address: {mac_address}, Device Type: {device_type}"
            )

    except KeyboardInterrupt:
        print("\nScanning stopped by user.")
        exit()
    except socket.gaierror:
        print("Hostname could not be resolved.")
        exit()
    except KeyError as e:
        print(f"An error occurred: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")


if __name__ == "__main__":
    scan(target_ip)
