# main.py
from netscan.scanner import NetworkScanner
from netscan.printer import TerminalPrinter


def main():
    network_range = "192.168.1.0/24"

    # Create an instance of NetworkScanner
    scanner = NetworkScanner(network_range)
    results = scanner.initial_scan()

    # Create an instance of TerminalPrinter
    printer = TerminalPrinter()
    printer.print_results(results)


if __name__ == "__main__":
    main()
