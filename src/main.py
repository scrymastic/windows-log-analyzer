




# Implement argparse


# Sample code for event filtering
from log_parser import LogParser
from filter_engine import FilterEngine
from rule_engine import RuleEngine
from reporter import Reporter
from pathlib import Path
import yaml
import os

# Initialize the log parser
log_parser = LogParser()
# Parse the log file
events = log_parser.parse_log_file("D:\AtSchool\windows-log-analyzer\sample-logs\sideloading_wwlib_sysmon_7_1_11.evtx")
# Initialize the rule engine
rule_engine = RuleEngine()

rules = rule_engine.load_rules()
# Initialize the filter engine

filter_engine = FilterEngine(rules)
# Filter the events
filtered_events = filter_engine.filter_events(events)

# print the filtered events
for event_id, rule_id_list in filtered_events.items():
    print(f"Event ID: {event_id}")
    print(f"Rule ID list: {rule_id_list}")
    print()



