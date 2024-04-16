
import json
from datetime import datetime, timezone, timedelta
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


    def parse_records_by_range(self, records: list, start: int, end: int) -> dict:
        events = {}
        if not start: start = 0
        if not end: end = len(records)
        for record in records[start:end]:
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
        if not start_time:
            start_time = "1970-01-01T00:00:00.000Z"
        if not end_time:
            end_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
        start_time = start_time.replace("T", " ").replace("Z", "")
        end_time = end_time.replace("T", " ").replace("Z", "")
        try:
            start_time = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S.%f') - timedelta(hours=TIMEZONE)
            end_time = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S.%f') - timedelta(hours=TIMEZONE)
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
    log_file_path = "D:\AtSchool\windows-log-analyzer\sample-logs\Privilege Escalation\\4765_sidhistory_add_t1178.evtx"
    events = log_parser.load_log_file(log_file_path)
    print(log_parser.parse_all_records(events))
