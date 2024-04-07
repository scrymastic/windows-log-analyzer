
import json
import os
from pathlib import Path
from evtx import PyEvtxParser

LOG_FILE = "D:\AtSchool\windows-log-analyzer\sample-logs\persistence_sysmon_11_13_1_shime_appfix.evtx"

def main(filepath) -> list:
    parser = PyEvtxParser(str(filepath))
    events = []
    for r in parser.records_json():
        data = json.loads(r["data"]).get("Event", {})

        print(data)
        
    return events

if __name__ == "__main__":
    main(Path(LOG_FILE))