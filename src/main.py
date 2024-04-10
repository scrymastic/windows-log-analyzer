




# Implement argparse


# Sample code for event filtering
from log_parser import LogParser
from filter_engine import FilterEngine
from rule_engine import RuleEngine
from reporter import Reporter
from pathlib import Path
from config import ROOT
import yaml
import os


# Initialize the log parser
log_parser = LogParser()
# Parse the log file
events = log_parser.parse_log_file("D:\AtSchool\windows-log-analyzer\sample-logs\Execution\exec_sysmon_1_11_lolbin_rundll32_shdocvw_openurl.evtx")
# events = [{'System': {'Channel': 'Security', 'Computer': 'PC02.example.corp', 'Correlation': None, 'EventID': 4624, 'EventRecordID': 5278, 'Execution': {'#attributes': {'ProcessID': 480, 'ThreadID': 1716}}, 'Keywords': '0x8020000000000000', 'Level': 0, 'Opcode': 0, 'Provider': {'#attributes': {'Guid': '54849625-5478-4994-A5BA-3E3B0328C30D', 'Name': 'Microsoft-Windows-Security-Auditing'}}, 'Security': None, 'Task': 12544, 'TimeCreated': {'#attributes': {'SystemTime': '2019-02-13T15:14:52.409734Z'}}, 'Version': 0}, 'EventData': {'AuthenticationPackageName': 'Negotiate', 'IpAddress': '-', 'IpPort': '-', 'KeyLength': 0, 'LmPackageName': '-', 'LogonGuid': '00000000-0000-0000-0000-000000000000', 'LogonProcessName': 'Advapi  ', 'LogonType': 5, 'ProcessId': '0x1d4', 'ProcessName': 'C:\\Windows\\System32\\services.exe', 'SubjectDomainName': 'EXAMPLE', 'SubjectLogonId': '0x3e7', 'SubjectUserName': 'PC02$', 'SubjectUserSid': 'S-1-5-18', 'TargetDomainName': 'NT AUTHORITY', 'TargetLogonId': '0x3e7', 'TargetUserName': 'SYSTEM', 'TargetUserSid': 'S-1-5-18', 'TransmittedServices': '-', 'WorkstationName': ''}}]
# Initialize the rule engine
rule_engine = RuleEngine()

rules = rule_engine.load_rules()
# Initialize the filter engine

filter_engine = FilterEngine(rules)
# Filter the events
filtered_events = filter_engine.filter_events(events)

# print the filtered events
for event_id, rule_id_list in filtered_events.items():
    print(f"EventRecordID: {event_id}")
    print(f"Rule ID list: {rule_id_list}")
    print()



