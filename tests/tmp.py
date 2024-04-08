

from evtx import PyEvtxParser
import json

# log_file = "D:\AtSchool\windows-log-analyzer\sample-logs\CA_Mimikatz_Memssp_Default_Logs_Sysmon_11.evtx"

# parser = PyEvtxParser("D:\AtSchool\windows-log-analyzer\sample-logs\sideloading_wwlib_sysmon_7_1_11.evtx")
# events = []

# for r in parser.records_json():
#     # print(r)
#     data = json.loads(r["data"]).get("Event", {})
#     event_id = data.get("System", {}).get("EventID", None)
#     print(event_id)
#     if event_id == 7:
#         print(data)

print("Hello World".split("|"))