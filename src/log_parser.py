
import json
from datetime import datetime, timezone
from pathlib import Path
from evtx import PyEvtxParser
from config import *


class LogParser:
    def __init__(self):
        pass


    def load_log_file(self, log_file: str) -> list:
        # if log file is a path, convert it to a string
        # PyEvtxParser only accepts string paths
        if isinstance(log_file, Path):
            log_file = str(log_file)

        try:
            parser = PyEvtxParser(log_file)
        except Exception as e:
            print(f"Error parsing log file: {e}")
            return []
        return list(parser.records_json())
    

    def parse_all_records(self, records: list) -> dict:
        events = {}
        for record in records:
            event = self.parse_record(record)
            events.update(event)
        return events


    def parse_first_n_records(self, records: list, max_records: int = None) -> dict:
        if not max_records:
            max_records = len(records)
        if max_records not in range(0, len(records) + 1):
            print(f"{RED}[ERROR] Invalid number of records to parse.{RESET}")
            return {}
        events = {}
        for record in records[:max_records]:
            event = self.parse_record(record)
            events.update(event)

        return events
    

    def parse_records_by_keyword(self, records: list, keywords: list) -> dict:
        events = {}
        for record in records:
            event = self.parse_record(record)
            if all(keyword.lower() in str(event).lower() for keyword in keywords):
                events.update(event)
        return events
    

    def parse_records_by_event_ids(self, records: list, event_ids: list) -> dict:
        events = {}
        for record in records:
            event = self.parse_record(record)
            if next(iter(event.values()))["System"]["EventID"] in event_ids:
                events.update(event)
        return events
    

    def parse_records_by_time_range(self, records: list, start_time: str, end_time: str) -> dict:
        events = {}
        if not records:
            print(f"{RED}[ERROR] No records found.{RESET}")
            return {}
        start_time = start_time.replace("T", " ").replace("Z", "")
        end_time = end_time.replace("T", " ").replace("Z", "")
        try:
            start_time = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S.%f')
            end_time = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S.%f')
        except ValueError:
            print(f"{RED}[ERROR] Invalid time format.{RESET}")
            return {}

        for record in records:
            event = self.parse_record(record)
            event_time = next(iter(event.values()))["System"]["TimeCreated"]["#attributes"]["SystemTime"].replace("T", " ").replace("Z", "")
            event_time = datetime.strptime(event_time, '%Y-%m-%d %H:%M:%S.%f')
            if start_time <= event_time <= end_time:
                events.update(event)
        return events



    def parse_record(self, record: dict) -> dict:
        data = json.loads(record["data"]).get("Event", {})
        # Only System and EventData fields are needed
        system_fields = data.get("System", {})
        eventdata_fields = data.get("EventData", {})
        event_record_id = system_fields.get("EventRecordID")
        return {event_record_id: {"System": system_fields, "EventData": eventdata_fields}}
    

if __name__ == "__main__":
    log_folder = Path(ROOT, "sample-logs")
    log_parser = LogParser()
    log_file_path = "D:\AtSchool\windows-log-analyzer\sample-logs\\UACME_59_Sysmon.evtx"
    events = log_parser.load_log_file(log_file_path)
    print(events)
