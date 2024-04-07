import json
import os
from pathlib import Path
from evtx import PyEvtxParser
from config import ROOT

SYSMON_LOG_MAPPING_FILE = Path(ROOT, "mapping", "logs", "mapping-windows-sysmon-logs.json")

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
        
        events = []
        with open(SYSMON_LOG_MAPPING_FILE, "r") as f:
            field_mapping_data = json.load(f)

        for record in parser.records_json():
            data = json.loads(record["data"]).get("Event", {})
            events.append(self.parse_event(data, field_mapping_data))
        return events


    def extract_fields(self, record, fields) -> dict:
        # "Default": {
        #     "Provider.#attributes.Name": "Provider",
        #     "EventID": "EventID",
        #     "EventRecordID": "EventRecordID",
        #     "TimeCreated.#attributes.SystemTime": "TimeCreated"
        # }
        # "EventID_1": {
        #     "Image": "Image",
        #     "Description": "Description",
        #     "Product": "Product",
        #     "Company": "Company",
        #     "CommandLine": "CommandLine",
        #     "User": "User",
        #     "ParentImage": "ParentImage",
        #     "ParentCommandLine": "ParentCommandLine"
        # }
        # Fields must be the top-level keys in the record, not nested fields

        extracted_fields = {}

        for original_field, new_field_name in fields.items():
            if "." in original_field:   # nested field
                nested_record = record
                fields_list = original_field.split(".")
                for field in fields_list:
                    nested_record = nested_record.get(field, {})
                extracted_fields[new_field_name] = nested_record
            else:
                extracted_fields[new_field_name] = record.get(original_field, "")
                
        return extracted_fields


    def parse_event(self, record, field_mapping_data) -> dict:
        system_data = record.get("System", {})
        event_data = record.get("EventData", {})
        
        formatted_event = {}

        formatted_event["System"] = self.extract_fields(system_data, field_mapping_data["Default"])
        try:
            formatted_event["EventData"] = self.extract_fields(event_data, field_mapping_data[f"EventID_{formatted_event['System']['EventID']}"])
        except KeyError:
            print(f"Event ID {formatted_event['System']['EventID']} not found in mapping file")
        return formatted_event
    


if __name__ == "__main__":
    log_folder = Path(ROOT, "sample-logs")
    log_parser = LogParser()
    log_file_path = log_folder / "sideloading_wwlib_sysmon_7_1_11.evtx"
    events = log_parser.parse_log_file(log_file_path)
    print(events)
        