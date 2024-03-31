import json
from pathlib import Path
from Evtx import PyEvtxParser

LOG_FILE = "D:\\windows-log-analyzer\\logs\\susp_explorer_exec.evtx"


def main(evtx_file: Path) -> list:
    parser = PyEvtxParser(str(evtx_file))
    events = []
    for r in parser.records_json():
        data = json.loads(r["data"]).get("Event", {})
        event = {
            "Provider": data.get("System", {}).get("Provider", {}).get("#attributes", {}).get("Name", ""),
            "EventID": data.get("System", {}).get("EventID", ""),
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


if __name__ == "__main__":
    events = main(Path(LOG_FILE))
    for event in events:
        print(json.dumps(event,ensure_ascii=False, indent=4))
