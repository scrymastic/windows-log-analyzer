

from pathlib import Path
import yaml
from data_access import DataAccess
from log_parser import LogParser
from log_analysis import LogAnalysis
from filter_engine import FilterEngine
from rule_engine import RuleEngine
from reporter import Reporter
from config import *
import os



class Main:
    def __init__(self):
        self.data_access = DataAccess()
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


    def search_log_files(self):
        print()
        print(f"  {CYAN}Search log files{RESET}")
        print()
        print(f"    1) Search in sample-logs")
        print(f"    2) Search in event-viewer-logs")
        print(f"  99) Back to main menu")
        print()
        log_folder = input(f"{RED}wla>search>{RESET} Enter log folder path: ").strip()
        if log_folder == "1":
            log_folder = self.data_access.sample_logs
        elif log_folder == "2":
            log_folder = self.data_access.event_viewer_logs
        elif log_folder == "99":
            return
        else:
            if not os.path.exists(log_folder) or not os.path.isdir(log_folder):
                print(f"{RED}[ERROR] Folder not found.{RESET}")
                return
        keywords = input(f"            Enter keyword to search: ")
        matching_log_files = self.data_access.search_log_files(log_folder, keywords.split(','))
        print()
        print(f"{GREEN}[INFO] Found {len(matching_log_files)} matching log files.{RESET}")
        for log_file in matching_log_files:
            print(f"{CYAN}Log file{RESET}: {log_file}")


    def load_log_file(self):
        print()
        print(f"  {CYAN}Load log file{RESET}")
        print()
        print(f"  99) Back to main menu")
        print()
        print(f"{YELLOW}The log file must be in EVTX format{RESET}")
        log_file_path = input(f"{RED}wla>load>{RESET} Enter the path to the log file: ").strip()
        if log_file_path == "99":
            return
        if not os.path.exists(log_file_path):
            print(f"{RED}[ERROR] Log file not found.{RESET}")
            return
        records = self.log_parser.load_log_file(log_file_path)
        if not records:
            print(f"{RED}[ERROR] Failed to load log file.{RESET}")
            return
        print(f"{GREEN}[INFO] Log file loaded successfully. Found {len(records)} records.{RESET}")

        while True:
            print()
            print(f"  {CYAN}Parse log file{RESET}")
            print()
            print(f"    1) Parse all records")
            print(f"    2) Parse records by range")
            print(f"    3) Parse records by event IDs")
            print(f"    4) Parse records by time range")
            print(f"    5) Parse records by keywords")
            print()
            print(f"  99) Back to main menu")
            print()
            choice = input(f"{RED}wla>load>{RESET} ").strip()

            if choice == "1":
                self.events = self.log_parser.parse_all_records(records)
                if not self.events:
                    print(f"{RED}[ERROR] Failed to parse log file.{RESET}")
                else:
                    print(f"{GREEN}[INFO] Parsed {len(self.events)} events.{RESET}")
                    self.log_analysis = LogAnalysis(self.events)
                return
        
            elif choice == "2":
                records_range = input(f"{RED}wla>load>parse>{RESET} Enter the range of records to parse (start, end), or press Enter to parse all records: ").strip()
                if not records_range:
                    self.events = self.log_parser.parse_all_records(records)
                    if not self.events:
                        print(f"{RED}[ERROR] Failed to parse log file.{RESET}")
                    else:
                        print(f"{GREEN}[INFO] Parsed {len(self.events)} events.{RESET}")
                        self.log_analysis = LogAnalysis(self.events)
                    return
                try:
                    start, end = [int(x.strip()) for x in records_range.split(',')]
                except:
                    print(f"{RED}[ERROR] Invalid range.{RESET}")
                    continue
                self.events = self.log_parser.parse_records_by_range(records, start, end)
                if not self.events:
                    print(f"{RED}[ERROR] No records found.{RESET}")
                else:
                    print(f"{GREEN}[INFO] Parsed {len(self.events)} events.{RESET}")
                    self.log_analysis = LogAnalysis(self.events)
                return
            
            elif choice == "3":
                event_ids = input(f"{RED}wla>load>parse>{RESET} Enter the event IDs, separated by commas: ")
                try:
                    event_ids = [int(event_id.strip()) for event_id in event_ids.split(',')]
                except:
                    print(f"{RED}[ERROR] Invalid event IDs.{RESET}")
                    continue
                self.events = self.log_parser.parse_records_by_event_ids(records, event_ids)
                if not self.events:
                    print(f"{RED}[ERROR] No records found.{RESET}")
                else:
                    print(f"{GREEN}[INFO] Parsed {len(self.events)} events.{RESET}")
                    self.log_analysis = LogAnalysis(self.events)
                return

            elif choice == "4":
                print()
                print(f"{YELLOW}Parse records by local time. The time format must be 'YYYY-MM-DD HH:MM:SS.MS'{RESET}")
                start_time = input(f"{RED}wla>load>parse>{RESET} Enter the start time, or press Enter to get the first record's time: ").strip()
                end_time = input(f"                Enter the end time, or press Enter to get the last record's time: ").strip()
                if not start_time:
                    start_time = next(iter(first_event.values()))['System']['TimeCreated']['#attributes']['SystemTime']
                if not end_time:
                    end_time = next(iter(last_event.values()))['System']['TimeCreated']['#attributes']['SystemTime']

                self.events = self.log_parser.parse_records_by_time_range(records, start_time, end_time)
                if not self.events:
                    print(f"{RED}[ERROR] No records found.{RESET}")
                else:
                    print(f"{GREEN}[INFO] Parsed {len(self.events)} events.{RESET}")
                    self.log_analysis = LogAnalysis(self.events)
                return

            elif choice == "5":
                keywords = input(f"{RED}wla>load>parse>{RESET} Enter keywords, separated by commas: ")
                keywords = keywords.split(',')
                self.events = self.log_parser.parse_records_by_keyword(records, keywords)
                if not self.events:
                    print(f"{RED}[ERROR] No records found.{RESET}")
                else:
                    print(f"{GREEN}[INFO] Parsed {len(self.events)} events.{RESET}")
                    self.log_analysis = LogAnalysis(self.events)
                return
            
            elif choice == "99":
                return
            else:
                print(f"{RED}[ERROR] Invalid choice.{RESET}")



    def filter_events(self):
        if not self.events:
            print(f"{YELLOW}Please load a log file first.{RESET}")
            return
        print()
        print(f"  {CYAN}Filtering events...{RESET}")
        print()
        filtered_events = self.filter_engine.filter_events(self.events)
        event_count = 0
        for filtered_event in filtered_events:
            event_id, rule_id_list = list(filtered_event.items())[0]
            self.reporter.alert(self.events[event_id], rule_id_list)
            event_count += 1
        if event_count == 0:
            print()
            print(f"{GREEN}[INFO] No events matched the filters.{RESET}")
        else:
            print()
            print(f"{GREEN}[INFO] {event_count} events matched the filters.{RESET}")
    

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
            choice = input(f"{RED}wla>events>{RESET} ").strip()
            if choice == "1":
                keywords = input(f"{RED}wla>events>search>{RESET} Enter keywords, separated by commas: ")
                keywords = keywords.split(',')
                matching_events = self.log_analysis.search_events(keywords)
                for event_record_id in matching_events:
                    self.reporter.show_event_summary(self.events[event_record_id])
            elif choice == "2":
                event_record_id = input(f"{RED}wla>events>show>{RESET} Enter the event record ID: ").strip()
                event = self.log_analysis.get_event(int(event_record_id))
                if event:
                    self.reporter.show_event_details(event)
                else:
                    print(f"{RED}[ERROR] Event not found.{RESET}")
            elif choice == "3":
                print()
                print(f"{GREEN}Total events: {len(self.events)}{RESET}")

                start_time, end_time = self.log_analysis.get_time_range()
                print(f"{CYAN}Time range{RESET}: {start_time} - {end_time}")
                print()
                print(f"{GREEN}Event distribution by Provider{RESET}")
                event_counts_by_provider = self.log_analysis.count_events_by_provider()
                self.reporter.show_distribution(event_counts_by_provider)
                print()
                print(f"{GREEN}Event distribution by Event ID{RESET}")
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
            print(f"    3) Deploy rule")
            print(f"    4) Undeploy rule")
            print()
            print(f"  99) Back to main menu")
            print()
            choice = input(f"{RED}wla>rules>{RESET} ").strip()
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
                rule_id = input(f"{RED}wla>rules>view>{RESET} Enter the rule ID: ").strip()
                rule = self.rule_engine.get_rule(rule_id)
                if rule:
                    self.reporter.show_rule_details(rule)
                else:
                    print(f"{RED}[ERROR] Rule not found.{RESET}")

            elif choice == "3":
                rule_file = input(f"{RED}wla>rules>deploy>{RESET} Enter the rule file path: ").strip()
                print()
                rule_id = self.rule_engine.deploy_rule(rule_file)
                if not rule_id:
                    print(f"{RED}[ERROR] Failed to deploy rule.{RESET}")
                    continue

                # Add the rule to the filter engine
                rule = self.rule_engine.load_rule(Path(self.rule_engine.active_rules_folder, "detections", f"{rule_id}.yml"))
                result = self.filter_engine.add_rule(rule)
                if result:
                    print(f"{GREEN}[INFO] Rule added to the filter engine.{RESET}")
                else:
                    print(f"{RED}[ERROR] Failed to add rule to the filter engine.{RESET}")

                print(f"{CYAN}[INFO] {len(self.filter_engine.rules)} rules in the filter engine.{RESET}")

            elif choice == "4":
                rule_id = input(f"{RED}wla>rules>undeploy>{RESET} Enter the rule ID: ").strip()
                print()
                if self.rule_engine.undeploy_rule(rule_id):
                    print(f"{GREEN}[INFO] Rule undeployed successfully.{RESET}")
                else:
                    print(f"{RED}[ERROR] Failed to undeploy rule.{RESET}")

                # Remove the rule from the filter engine
                result = self.filter_engine.remove_rule(rule_id)
                if result:
                    print(f"{GREEN}[INFO] Rule removed from the filter engine.{RESET}")
                else:
                    print(f"{RED}[ERROR] Failed to remove rule from the filter engine.{RESET}")

                print(f"{CYAN}[INFO] {len(self.filter_engine.rules)} rules in the filter engine.{RESET}")

            elif choice == "99":
                break
            else:
                print(f"{RED}[ERROR] Invalid choice.{RESET}")





    def main(self): 
        self.banner()
        print(f"{CYAN}[INFO] Initializing...{RESET}")
        self.log_parser = LogParser()
        self.rule_engine = RuleEngine()
        self.filter_engine = FilterEngine(rules=self.rule_engine.load_default_rules())
        self.reporter = Reporter()
        print(f"{GREEN}[INFO] Initialization completed.{RESET}")

        while True:
            print()
            print(f"  Select from the menu:")
            print()
            print(f"    1) Search log files")
            print(f"    2) Load log file")
            print(f"    3) Filter events")
            print(f"    4) Analyze events")
            print(f"    5) Rules management")
            print()
            print(f"  99) Exit the windows log analyzer")
            print()
            choice = input(f"{RED}wla>{RESET} ").strip()
            if choice == "1":
                self.search_log_files()
            elif choice == "2":
                self.load_log_file()
            elif choice == "3":
                self.filter_events()
            elif choice == "4":
                self.analyze_events()
            elif choice == "5":
                self.rules_management()

            elif choice == "99":
                print(f"{CYAN}[INFO] Exiting the Windows Log Analyzer...{RESET}")
                break
            else:
                print(f"{RED}[ERROR] Invalid choice.{RESET}")


if __name__ == "__main__":
    main = Main()
    main.main()

