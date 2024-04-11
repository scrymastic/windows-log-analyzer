import os
import json
from pathlib import Path
from Evtx.evtx import PyEvtxParser

class LogParser:
    def __init__(self):
        pass

    def parse_log_file(self, log_file: str) -> list:
        # PyEvtxParser only accepts string paths
        if isinstance(log_file, Path):
            log_file = str(log_file)

        try:
            parser = PyEvtxParser(log_file)
        except Exception as e:
            print(f"Error parsing log file: {e}")
            return []
        
        events = []
        for i, record in enumerate(parser.records_json()):
            data = json.loads(record["data"]).get("Event", {})
            # Only System and EventData fields are needed
            system_fields = data.get("System", {})
            eventdata_fields = data.get("EventData", {})
            event = {
                "System": system_fields,
                "EventData": eventdata_fields
            }
            events.append(event)

            # Tạo thư mục log nếu chưa tồn tại
            if not os.path.exists('log'):
                os.makedirs('log')

            # Tạo tên file dựa trên chỉ số của sự kiện
            filename = f"log/event_{i}.json"
            # Ghi sự kiện vào file
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(event, f)

        return events

if __name__ == "__main__":
    log_parser = LogParser()
    log_file_path = r"D:\KMA\KMA N3.3\Kỹ thuật lập trình\windows-log-analyzer\data_access\Sysmon.evtx"  # Thay đổi đường dẫn này tới file log của bạn
    events = log_parser.parse_log_file(log_file_path)