
from events.event import EventType, EventMethod
from utils.logger import logger
from pathlib import Path
from evtx import PyEvtxParser
from typing import Dict, List
import json



class LogParser:
    """
    A class that implements a log parser for parsing Windows Event Viewer log files.
    """
    def __init__(self):
        pass


    def parse_log_file(self, log_path: Path) -> List[EventType]:
        try:
            log_path = str(log_path)    # PyEvtxParser only accepts string path
            parser = PyEvtxParser(log_path)
            events = []
            for record in parser.records_json():
                event = self.parse_record(record)
                if event is not None:
                    events.append(event)
            return events
        except Exception as e:
            logger.error(f"Failed to parse {log_path}, error: {e}")


    def parse_record(self, record: Dict) -> EventType:
        data = json.loads(record["data"]).get("Event", {})
        # Only System and EventData fields are needed
        event = {
            "System": data.get("System", {}), 
            "EventData": data.get("EventData", {})
            }
        event = EventMethod.assign_event_universal_id(event)
        return event
        

if __name__ == "__main__":
    from config import ROOT
    log_folder = ROOT / "sample-logs"
    log_parser = LogParser()
    log_file_path = r"D:\AtSchool\windows-log-analyzer\sample-logs\AutomatedTestingTools\panache_sysmon_vs_EDRTestingScript.evtx"
    print(log_parser.parse_log_file(log_file_path))
