

from src.rules.rule_engine import RuleEngine
from src.rules.rule import RuleType, RuleMethod
from src.events.event import EventType, EventMethod
from src.config import RESET, RED, CYAN, YELLOW, GREEN
from typing import Dict, List


class Reporter:
    def __init__(self):
        pass

    def alert(self, event: Dict, rule_id_list: List[str]) -> None:
        # Report the event to the user
        print()
        print(f"{RED}ALERT! ALERT! ALERT!{RESET}")
        print(f"{CYAN}EVENT [{RED}{EventMethod.get_field(event, 'UniversalID')}{CYAN}]{RESET}")
        self.show_event_summary(event)

        print(f"{YELLOW}Has been detected by {len(rule_id_list)} rules:{RESET}")
        for rule_id in rule_id_list:
            rule = RuleEngine.get_rule_content_by_id(rule_id)
            print(f"{CYAN}RULE [{RED}{rule_id}{CYAN}]{RESET}")
            self.show_rule_summary(rule)

    
    def show_rule_details(self, rule: RuleType) -> None:
        self.pretty_print_dict(rule)

    
    def show_rule_summary(self, rule: RuleType) -> None:
        print()
        print(f"{CYAN}Title{RESET}: {RuleMethod.get_field(rule, 'title')}")
        level = RuleMethod.get_field(rule, 'level')
        if level == "high":
            print(f"{CYAN}Level{RESET}: {RED}{level}{RESET}")
        elif level == "medium":
            print(f"{CYAN}Level{RESET}: {YELLOW}{level}{RESET}")
        elif level == "low":
            print(f"{CYAN}Level{RESET}: {GREEN}{level}{RESET}")
        else:
            print(f"{CYAN}Level{RESET}: {level}")
        print(f"{CYAN}Description{RESET}: {RuleMethod.get_field(rule, 'description')}")
        print(f"{CYAN}Tags{RESET}: {', '.join(RuleMethod.get_field(rule, 'tags'))}")
        print()


    
    def show_event_details(self, event: EventType) -> None:
        self.pretty_print_dict(event)

    
    def show_event_summary(self, event: EventType) -> None:
        print()
        print(f"{CYAN}Event Record ID{RESET}: {EventMethod.get_field(event, 'System', 'EventRecordID')}")
        print(f"{CYAN}Time Created{RESET}: {EventMethod.get_field(event, 'System', 'TimeCreated', '#attributes', 'SystemTime')}")
        print(f"{CYAN}Provider{RESET}: {EventMethod.get_field(event, 'System', 'Provider', '#attributes', 'Name')}")
        print(f"{CYAN}Event ID{RESET}: {EventMethod.get_field(event, 'System', 'EventID')}")
        print(f"{CYAN}Computer{RESET}: {EventMethod.get_field(event, 'System', 'Computer')}")
        print()


    def show_distribution(self, data: Dict[str, int]) -> None:
        print()
        total = sum(data.values())
        # Get the length of the longest key
        length_key = max(len(str(key)) for key in data.keys())
        length_key = max(length_key, 5)
        for key, value in data.items():
            percentage = value / total * 100
            length_of_bar = int(percentage / 100 * 60)
            print(f"{CYAN}{key:<{length_key}}{RESET}: {YELLOW}{'#' * length_of_bar}{RESET} {value} ({percentage:.2f}%)")


    def pretty_print_dict(self, data: Dict, indent: int = 0) -> None:
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
