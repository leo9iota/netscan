# netscan/printer.py
from tabulate import tabulate
from termcolor import colored


class TerminalPrinter:
    def print_results(self, results):
        headers = ["IP Address", "MAC Address", "Possible OS"]
        print(colored(tabulate(results, headers=headers, tablefmt="grid"), "green"))

    def print_banner(self):
        banner = """
                          888                                        
                          888                                        
                          888                                        
        88888b.   .d88b.  888888 .d8888b   .d8888b  8888b.  88888b.  
        888 "88b d8P  Y8b 888    88K      d88P"        "88b 888 "88b 
        888  888 88888888 888    "Y8888b. 888      .d888888 888  888 
        888  888 Y8b.     Y88b.       X88 Y88b.    888  888 888  888 
        888  888  "Y8888   "Y888  88888P'  "Y8888P "Y888888 888  888 
        """
        print(banner)