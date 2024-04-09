from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view
import os
import uuid
import yaml
from xml.etree.ElementTree import fromstring
import xmltodict

def get_event_data(file):
    try:
        with Evtx(file) as log:
            for record_xml, record in evtx_file_xml_view(log.get_file_header()):
                yield record_xml
    except FileNotFoundError:
        print(f"File {file} not found.")
        return

def parse_event(event_xml):
    try:
        event_dict = xmltodict.parse(event_xml)
        # Simplify the event data structure
        simplified_event = {}
        for item in event_dict['Event']['EventData']['Data']:
            key = item['@Name']
            value = item['#text']
            simplified_event[key] = value
        # Add System information
        for key, value in event_dict['Event']['System'].items():
            if isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    simplified_event[f"{key}_{sub_key}"] = sub_value
            else:
                simplified_event[key] = value
        return simplified_event
    except Exception as e:
        print(f"Error parsing event: {e}")
        return None

try:
    os.makedirs('data_access', exist_ok=True)
except Exception as e:
    print(f"Error creating directory: {e}")

# Get the path to the Security.evtx file
security_log_path = os.path.join(os.environ['SystemRoot'], 'System32', 'Winevt', 'Logs', 'Security.evtx')

for event_xml in get_event_data(security_log_path):
    event = parse_event(event_xml)
    if event is not None:
        # Write event_info to a YAML file
        filename = f"data_access/{uuid.uuid4()}.yaml"
        try:
            with open(filename, 'w') as file:
                yaml.dump(event, file)
        except Exception as e:
            print(f"Error writing to file {filename}: {e}")