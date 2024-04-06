import json
import os
from pathlib import Path
from Evtx import PyEvtxParser
#from config import ROOT

LOG_FILE = "C:\\Users\\Long\\OneDrive - actvn.edu.vn\\Máy tính\\project\\windows-log-analyzer\\sample-logs\\LM_typical_IIS_webshell_sysmon_1_10_traces.evtx"


def main(filepath) -> list:
    parser = PyEvtxParser(str(filepath))
    events = []
    for r in parser.records_json():
        data = json.loads(r["data"]).get("Event", {})
        if data.get("System", {}).get("EventID", "")==1:
            event = event1(data)
            events.append(event)
        elif data.get("System", {}).get("EventID", "")==3:
            event = event3(data)
            events.append(event)
        elif data.get("System", {}).get("EventID", "")==13:
            event = event13(data)
            events.append(event)
        
    return events
directory="C:\\Users\\Long\\OneDrive - actvn.edu.vn\\Máy tính\\project\\windows-log-analyzer\\sample-logs\\"
def read_files_in_directory(directory) -> list:
    events = []
    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        if os.path.isfile(filepath):
            events.append(main(filepath))
    return events

def event1(data) -> list:
    events = []
    event = {
        "Provider": data.get("System", {}).get("Provider", {}).get("#attributes", {}).get("Name", ""),
        "EventID": data.get("System", {}).get("EventID", ""),
        "EventRecordID": data.get("System",{}).get("EventRecordID",""),
        "TimeCreated": data.get("System", {}).get("TimeCreated", {}).get("#attributes",{}).get("SystemTime",""),
        "EventData": {
            "Image": data.get("EventData", {}).get("Image", ""),
            "Description": data.get("EventData", {}).get("Description", ""),
            "Product": data.get("EventData", {}).get("Product", ""),
            "Company": data.get("EventData", {}).get("Company", ""),
            "CommandLine": data.get("EventData", {}).get("CommandLine", ""),
            "User": data.get("EventData", {}).get("User", ""),
            "ParentImage": data.get("EventData", {}).get("ParentImage", ""),
            "ParentCommandLine": data.get("EventData", {}).get("ParentCommandLine", ""),
        }
    }
    events.append(event)
    return events

def event3(data) -> list:
    events = []
    event = {
        "Provider": data.get("System", {}).get("Provider", {}).get("#attributes", {}).get("Name", ""),
        "EventID": data.get("System", {}).get("EventID", ""),
        "EventRecordID": data.get("System",{}).get("EventRecordID",""),
        "TimeCreated": data.get("System", {}).get("TimeCreated", {}).get("#attributes",{}).get("SystemTime",""),
        "EventData": {
            "Image": data.get("EventData", {}).get("Image", ""),
            "User": data.get("EventData", {}).get("User", ""),
            "Protocol": data.get("EventData", {}).get("Protocol", ""),
            "Initiated": data.get("EventData", {}).get("Initiated", ""),
            "SourceIsIpv6": data.get("EventData", {}).get("SourceIsIpv6", ""),
            "SourceIp": data.get("EventData", {}).get("SourceIp", ""),
            "SourceHostname": data.get("EventData", {}).get("SourceHostname", ""),
            "SourcePort": data.get("EventData", {}).get("SourcePort", ""),
            "SourcePortName": data.get("EventData", {}).get("SourcePortName", ""),
            "DestinationIsIpv6": data.get("EventData", {}).get("DestinationIsIpv6", ""),
            "DestinationIp": data.get("EventData", {}).get("DestinationIp", ""),
            "DestinationHostname": data.get("EventData", {}).get("DestinationHostname", ""),
            "DestinationPort": data.get("EventData", {}).get("DestinationPort", ""),
            "DestinationPortName": data.get("EventData", {}).get("DestinationPortName", ""),
            }
        }
    events.append(event)
    return events

def event13(data) -> list:
    events = []
    event = {
            "Provider": data.get("System", {}).get("Provider", {}).get("#attributes", {}).get("Name", ""),
            "EventID": data.get("System", {}).get("EventID", ""),
            "EventRecordID": data.get("System",{}).get("EventRecordID",""),
            "TimeCreated": data.get("System", {}).get("TimeCreated", {}).get("#attributes",{}).get("SystemTime",""),
            "EventData": {
                "Image": data.get("EventData", {}).get("Image", ""),
                "TargetObject": data.get("EventData", {}).get("TargetObject", ""),
                "EventType": data.get("EventData", {}).get("EventType", ""),
                "Details": data.get("EventData", {}).get("Details", ""),
            }
        }
    events.append(event)
    return events
if __name__ == "__main__":
    events = read_files_in_directory(directory)
    for event in events:
        print(json.dumps(event,ensure_ascii=False, indent=4))