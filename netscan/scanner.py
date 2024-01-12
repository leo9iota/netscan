# netscan/scanner.py
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp
import nmap
import threading


class NetworkScanner:
    def __init__(self, ip_range):
        self.ip_range = ip_range
        self.nm = nmap.PortScanner()
        self.results = []
        self.lock = threading.Lock()

    def scan_host(self, ip_address):
        try:
            self.nm.scan(hosts=ip_address, arguments="-O -sV")
            os_info = []
            if "up" == self.nm[ip_address].state():
                if "osmatch" in self.nm[ip_address]:
                    for osmatch in self.nm[ip_address]["osmatch"]:
                        os_info.append(f"{osmatch['name']} ({osmatch['accuracy']}%)")
                else:
                    os_info.append("Not Detected")
                with self.lock:
                    self.results.append(
                        [
                            ip_address,
                            self.nm[ip_address]["addresses"].get("mac", "Not Detected"),
                            "\n".join(os_info),
                        ]
                    )
        except Exception as e:
            with self.lock:
                self.results.append([ip_address, "Error", str(e)])

    def initial_scan(self):
        arp_request = ARP(pdst=self.ip_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list, _ = srp(arp_request_broadcast, timeout=1, verbose=False)

        threads = []
        for _, received in answered_list:
            ip_address = received.psrc
            thread = threading.Thread(target=self.scan_host, args=(ip_address,))
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()

        return self.results
