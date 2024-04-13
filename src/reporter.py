
from colorama import Fore, Style
from config import ROOT
import yaml
import json
from pathlib import Path

RED = Fore.RED
LIGHTRED = Fore.LIGHTRED_EX
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
CYAN = Fore.CYAN
RESET = Style.RESET_ALL



class Reporter:
    def __init__(self):
        pass

    def alert(self, event, rule_id_list: list) -> None:
        # Report the event to the user
        # Get the rule title from /active-rules/headers/{rule_id}.yml
        # Get the rule metadata from /active-rules/metadata/{rule_id}.yml
        # Print the alert
        print()
        print(f"{LIGHTRED}ALERT! ALERT! ALERT!{RESET}")
        print(f"{CYAN}EVENT [{RED}{event['System']['EventRecordID']}{CYAN}]{RESET}")
        self.show_event_summary(event)

        print(f"{YELLOW}Has been detected by {len(rule_id_list)} rules:{RESET}")
        for rule_id in rule_id_list:
            with open(Path(ROOT) / "rules" / "active-rules" / "metadata" / f"{rule_id}.yml", "r") as f:
                rule_metadata = yaml.safe_load(f)
            print(f"{CYAN}RULE [{RED}{rule_id}{CYAN}]{RESET}")
            self.show_rule_summary(rule_metadata)

    
    def show_rule_details(self, rule) -> None:
        self.pretty_print_dict(rule)

    
    def show_rule_summary(self, rule_metadata) -> None:
        print()
        print(f"{CYAN}Title{RESET}: {rule_metadata['title']}")
        level = rule_metadata['level']
        if level == "high":
            print(f"{CYAN}Level{RESET}: {RED}{level}{RESET}")
        elif level == "medium":
            print(f"{CYAN}Level{RESET}: {YELLOW}{level}{RESET}")
        elif level == "low":
            print(f"{CYAN}Level{RESET}: {GREEN}{level}{RESET}")
        else:
            print(f"{CYAN}Level{RESET}: {level}")
        print(f"{CYAN}Description{RESET}: {rule_metadata['description']}")
        print(f"{CYAN}Tags{RESET}: {', '.join(rule_metadata['tags'])}")
        print()


    
    def show_event_details(self, event) -> None:
        self.pretty_print_dict(event)

    
    def show_event_summary(self, event) -> None:
        print()
        print(f"{CYAN}Event Record ID{RESET}: {event['System']['EventRecordID']}")
        print(f"{CYAN}Time Created{RESET}: {event['System']['TimeCreated']['#attributes']['SystemTime']}")
        print(f"{CYAN}Provider{RESET}: {event['System']['Provider']['#attributes']['Name']}")
        print(f"{CYAN}Event ID{RESET}: {event['System']['EventID']}")
        print(f"{CYAN}Computer{RESET}: {event['System']['Computer']}")
        print()


    def show_distribution(self, data: dict) -> None:
        print()
        total = sum(data.values())
        length = 60
        for key, value in data.items():
            percentage = value / total * length
            print(f"{CYAN}{key:<5}{RESET}: {YELLOW}{'#' * int(percentage)}{RESET} {round(percentage, 2)}%")


    def pretty_print_dict(self, data: dict, indent: int = 0) -> None:
        for key, value in data.items():
            print(f"{' ' * indent}{CYAN}{key}{RESET}: ", end="")
            if isinstance(value, (int, str)):
                print(f"{value}")
            elif isinstance(value, dict):
                print()
                self.pretty_print_dict(value, indent + 2)
            elif isinstance(value, list):
                print()
                for item in value:
                    if isinstance(item, (int, str)):
                        print(f"{item}")
                    else:
                        self.pretty_print_dict(item, indent + 4)
            else:
                print(f"{value}")
