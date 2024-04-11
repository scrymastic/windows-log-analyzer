
import json
from pathlib import Path
from Evtx.evtx import PyEvtxParser
from config import ROOT


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
        for record in parser.records_json():
            data = json.loads(record["data"]).get("Event", {})
            # Only System and EventData fields are needed
            system_fields = data.get("System", {})
            eventdata_fields = data.get("EventData", {})
            events.append({
                "System": system_fields,
                "EventData": eventdata_fields
            })

        return events
    

if __name__ == "__main__":
    log_folder = Path(ROOT, "data_access")
    log_parser = LogParser()
    log_file_path = log_folder / "Sysmon.evtx"
    events = log_parser.parse_log_file(log_file_path)
    print(events)
    
    with open("output.json", "w") as f:
        json.dump(events, f)