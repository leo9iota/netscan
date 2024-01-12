# netscan/display.py
from tabulate import tabulate
from termcolor import colored


def print_results(results):
    headers = ["IP Address", "MAC Address", "Possible OS"]
    print(colored(tabulate(results, headers=headers, tablefmt="grid"), "green"))
