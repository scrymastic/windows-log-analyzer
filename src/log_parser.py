
import json
from pathlib import Path
from evtx import PyEvtxParser
from config import ROOT
from colorama import Fore, Style

RED = Fore.RED
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
CYAN = Fore.CYAN
RESET = Style.RESET_ALL


class LogParser:
    def __init__(self):
        pass

    def parse_log_file(self, log_file: str) -> list:
        # if log file is a path, convert it to a string
        # PyEvtxParser only accepts string paths
        if isinstance(log_file, Path):
            log_file = str(log_file)

        try:
            parser = PyEvtxParser(log_file)
        except Exception as e:
            print(f"Error parsing log file: {e}")
            return []
        
        events = {}
        for record in parser.records_json():
            data = json.loads(record["data"]).get("Event", {})
            # Only System and EventData fields are needed
            system_fields = data.get("System", {})
            event_record_id = system_fields.get("EventRecordID")
            eventdata_fields = data.get("EventData", {})
            events.update({event_record_id: {"System": system_fields, "EventData": eventdata_fields}})

        return events
    

if __name__ == "__main__":
    log_folder = Path(ROOT, "sample-logs")
    log_parser = LogParser()
    log_file_path = "D:\AtSchool\windows-log-analyzer\sample-logs\\UACME_59_Sysmon.evtx"
    events = log_parser.parse_log_file(log_file_path)
    print(events)
