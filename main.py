# main.py
from netscan.scanner import NetworkScanner
from netscan.display import print_results


def main():
    network_range = "192.168.1.0/24"
    scanner = NetworkScanner(network_range)
    results = scanner.initial_scan()
    print_results(results)


if __name__ == "__main__":
    main()
