


# Sample code for event filtering
from log_parser import LogParser
from log_analysis import LogAnalysis
from filter_engine import FilterEngine
from rule_engine import RuleEngine
from reporter import Reporter
from pathlib import Path
from config import ROOT
import yaml
import os


from colorama import Fore, Style
RED = Fore.RED
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
CYAN = Fore.CYAN
MAGENTA = Fore.MAGENTA
RESET = Style.RESET_ALL


class Main:
    def __init__(self):
        self.log_parser = None
        self.log_analysis = None
        self.rule_engine = None
        self.filter_engine = None
        self.reporter = None
        self.events = None


    def banner(self):
        text = """
                            ..             
            x=~              x .d88"              
           88x.   .e.   .e.   5888R               
          '8888X.x888:.x888   '888R         u     
           `8888  888X '888k   888R      us888u.  
            X888  888X  888X   888R   .@88 "8888" 
            X888  888X  888X   888R   9888  9888  
            X888  888X  888X   888R   9888  9888  
           .X888  888X. 888~   888R   9888  9888  
           `%88%``"*888Y"     .888B . 9888  9888  
             `~     `"        ^*888%  "888*""888" 
                                "%     ^Y"   ^Y'  
        """
        lines = text.split('\n')
        lines = [line.center(60) for line in lines]
        text = '\n'.join(lines)
        print(f"{MAGENTA}{text}{RESET}")
        print(f"      {GREEN}{'Welcome to'.center(60)}{RESET}      ")
        print(f"[----]{CYAN}{'Windows Log Analyzer (wla)'.center(60)}{RESET}[----]")
        print(f"[----]{CYAN}{'Version 1.0.0'.center(60)}{RESET}[----]")
        print(f"[----]{RED}{'Github: https://github.com/scrymastic'.center(60)}{RESET}[----]")
        print()

    def load_log_file(self):
        print()
        print(f"  {CYAN}Load log file{RESET}")
        print()
        print(f"  99) Back to main menu")
        print()
        print(f"{YELLOW}The log file must be in EVTX format{RESET}")
        log_file_path = input(f"{RED}wla>load>{RESET} Enter the path to the log file: ")
        if log_file_path == "99":
            return
        print()
        print(f"{CYAN}[INFO] Loading log file...{RESET}")
        self.events = self.log_parser.parse_log_file(log_file_path)
        self.log_analysis = LogAnalysis(self.events)
        print(f"{GREEN}[INFO] Completed loading log file. Found {len(self.events)} events.{RESET}")


    def filter_events(self):
        if not self.events:
            print(f"{YELLOW}Please load a log file first.{RESET}")
            return
        print()
        print(f"  {CYAN}Filtering events...{RESET}")
        print()
        filtered_events = self.filter_engine.filter_events(self.events)
        if not filtered_events:
            print()
            print(f"{GREEN}[INFO] No events matched the filters.{RESET}")
            return
        for event_id, rule_id_list in filtered_events.items():
            self.reporter.alert(self.events[event_id], rule_id_list)

    
    def analyze_events(self):
        if not self.events or not self.log_analysis:
            print(f"{YELLOW}Please load a log file first.{RESET}")
            return
        while True:
            print()
            print(f"  {CYAN}Analyze events{RESET}")
            print()
            print(f"    1) Search for event")
            print(f"    2) Show event")
            print(f"    3) View event summary")
            print()
            print(f"  99) Back to main menu")
            print()
            choice = input(f"{RED}wla>events>{RESET} ")
            if choice == "1":
                keywords = input(f"{RED}wla>events>search>{RESET} Enter keywords, separated by commas: ")
                keywords = keywords.split(',')
                matching_events = self.log_analysis.search_events(keywords)
                for event_record_id in matching_events:
                    self.reporter.show_event_summary(self.events[event_record_id])
            elif choice == "2":
                event_record_id = input(f"{RED}wla>events>show>{RESET} Enter the event record ID: ")
                event = self.log_analysis.get_event(int(event_record_id))
                if event:
                    self.reporter.show_event_details(event)
                else:
                    print(f"{RED}[ERROR] Event not found.{RESET}")
            elif choice == "3":
                print()
                print(f"{GREEN}Total events: {len(self.events)}{RESET}")
                event_counts_by_id = self.log_analysis.count_events_by_id()
                self.reporter.show_distribution(event_counts_by_id)

            elif choice == "99":
                break
            else:
                print(f"{RED}[ERROR] Invalid choice.{RESET}")


    def rules_management(self):
        while True:
            print()
            print(f"  {CYAN}Rules management{RESET}")
            print()
            print(f"    1) Search for rules")
            print(f"    2) View rule")
            print()
            print(f"  99) Back to main menu")
            print()
            choice = input(f"{RED}wla>rules>{RESET} ")
            if choice == "1":
                keywords = input(f"{RED}wla>rules>search>{RESET} Enter keywords, separated by commas: ")
                keywords = keywords.split(',')
                matching_rule_ids = self.rule_engine.search_rules(keywords)
                print(f"{CYAN}[INFO] Found {len(matching_rule_ids)} matching rules.{RESET}")
                for rule_id in matching_rule_ids:
                    print(f"{CYAN}Rule ID{RESET}: {rule_id}")
                    rule = self.rule_engine.get_rule(rule_id)
                    self.reporter.show_rule_summary(rule)
            elif choice == "2":
                rule_id = input(f"{RED}wla>rules>view>{RESET} Enter the rule ID: ")
                rule = self.rule_engine.get_rule(rule_id)
                self.reporter.show_rule_details(rule)

            elif choice == "99":
                break
            else:
                print(f"{RED}[ERROR] Invalid choice.{RESET}")






    def main(self): 
        self.banner()
        print(f"{CYAN}[INFO] Initializing...{RESET}")
        self.log_parser = LogParser()
        self.rule_engine = RuleEngine()
        self.filter_engine = FilterEngine(rules=self.rule_engine.load_rules())
        self.reporter = Reporter()
        print(f"{GREEN}[INFO] Initialization completed.{RESET}")

        while True:
            print()
            print(f"  Select from the menu:")
            print()
            print(f"    1) Load log file")
            print(f"    2) Filter events")
            print(f"    3) Analyze events")
            print(f"    4) Rules management")
            print()
            print(f"  99) Exit the windows log analyzer")
            print()
            choice = input(f"{RED}wla>{RESET} ")
            if choice == "1":
                self.load_log_file()
            elif choice == "2":
                self.filter_events()
            elif choice == "3":
                self.analyze_events()
            elif choice == "4":
                self.rules_management()

            elif choice == "99":
                print(f"{CYAN}[INFO] Exiting the Windows Log Analyzer...{RESET}")
                break
            else:
                print(f"{RED}[ERROR] Invalid choice.{RESET}")


if __name__ == "__main__":
    main = Main()
    main.main()

