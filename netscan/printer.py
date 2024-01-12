# netscan/printer.py
from tabulate import tabulate
from termcolor import colored


class TerminalPrinter:
    def print_results(self, results):
        headers = ["IP Address", "MAC Address", "Possible OS"]
        print(colored(tabulate(results, headers=headers, tablefmt="grid"), "green"))
