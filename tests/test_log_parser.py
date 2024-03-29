
from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view
import xml.etree.ElementTree as ET

LOG_FILE = "D:\\AtSchool\\windows-log-analyzer\\logs\\evasion_persis_hidden_run_keyvalue_sysmon_13.evtx"

def print_records(file_path):
    with Evtx(file_path) as log:
        for record in log.records():
            # Extract EventID
            xml = evtx_file_xml_view(record)
            root = ET.fromstring(xml)
            event_id = root.find(".//EventID").text
            print(event_id)

print_records(LOG_FILE)

