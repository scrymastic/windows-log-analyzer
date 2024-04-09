
import regex

class FilterEngine:
    def __init__(self, rules):
        self.rules = rules


    def matches_rule(self, rule, event) -> bool:
        logsource = rule.get('logsource', None)
        if not logsource:
            print(f"Logsource not found in rule {rule}")
            return False
        if not self.match_event_id(logsource, event):
            return False
        # detection
        detection = rule.get('detection', None)

        if len(detection) != 1:
            print(f"Invalid rule '{rule}'")
            return False
        # Extract the rule from the detection, which is an 'and' block
        detection = detection[0]

        # Check if all conditions in the 'and' list are satisfied
        if not self.matches_and_block(detection['and'], event):
            return False
        return True


    def matches_and_block(self, block, event) -> bool:
        # Check if all conditions in the 'and' list are satisfied
        for condition in block:
            if not self.matches_condition(condition, event):
                return False
        return True


    def matches_or_block(self, block, event):
        # Check if any condition in the 'or' list is satisfied
        for condition in block:
            if self.matches_condition(condition, event):
                return True
        return False


    def matches_condition(self, condition, event):
        if not isinstance(condition, dict):
            print(f"Invalid condition '{condition}'")
            return False

        # If the condition is a block
        if len(condition) == 1:
            key = next(iter(condition))
            if key == 'and':
                return self.matches_and_block(condition[key], event)
            elif key == 'or':
                return self.matches_or_block(condition[key], event)
        
        # If the condition is a simple comparison
        # Extract the key and value from the condition
        key, value = next(iter(condition.items()))
        field, operator = key.split('|')

        # Extract the field value from the event data
        field_value = self.get_field_value(event, field)
        if field_value is None:
            # print(f"Field '{field}' not found in event {event}")
            return False
        # Perform the comparison based on the operator
        if operator == '==':
            return field_value == value
        elif operator == '!==':
            return field_value != value
        elif operator == 'contains':
            return value in field_value
        elif operator == 'not contains':
            return value not in field_value
        elif operator == 'startswith':
            return field_value.startswith(value)
        elif operator == 'not startswith':
            return not field_value.startswith(value)
        elif operator == 'endswith':
            return field_value.endswith(value)
        elif operator == 'not endswith':
            return not field_value.endswith(value)
        elif operator == 'matches':
            return regex.match(value, field_value)
        elif operator == 'not matches':
            return not regex.match(value, field_value)
        elif operator == 'cidr':    # for ip address, Classless Inter-Domain Routing
            from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network
            return IPv4Address(field_value) in IPv4Network(value) \
                if '.' in field_value else \
                IPv6Address(field_value) in IPv6Network(value)
        elif operator == 'not cidr':
            from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network
            return IPv4Address(field_value) not in IPv4Network(value) \
                if '.' in field_value else \
                IPv6Address(field_value) not in IPv6Network(value)
        else:
            print(f"Invalid operator '{operator}, key: {key}, value: {value}'")
            return False


    def get_field_value(self, event, field):
        # Extract the field value from the event data
        if field == 'EventID':
            return event.get('System', {}).get(field, None)
        else:
            return event.get('EventData', {}).get(field, None)
        
    
    def match_event_id(self, logsource, event) -> bool:
        # Check if "Microsoft-Windows-Sysmon"
        # Only Sysmon events are considered, other events are ignored
        try:
            provider = event['System']['Provider']['#attributes']['Name']
        except KeyError:
            return True
        if provider != 'Microsoft-Windows-Sysmon':
            return True
        
        event_ids_sysmon = {
            "process_creation": 1,
            "file_change": 2,
            "network_connection": 3,
            "sysmon_status": 4,
            "process_termination": 5,
            "driver_load": 6,
            "image_load": 7,
            "create_remote_thread": 8,
            "raw_access_thread": 9,
            "process_access": 10,
            "file_event": 11,
            "registry_add": 12,
            "registry_delete": 13,
            "registry_set": 14,
            "create_stream_hash": 15,
            "pipe_created": 17,
            "wmi_event": 19,
            "dns_query": 22,
            "file_delete": 23,
            "clipboard_change": 24,
            "process_tampering": 25,
            "file_delete_detected": 26,
            "file_block_executable": 27,
            "file_block_shredding": 28,
            "file_executable_detected": 29,
            "sysmon_error": 255
        }


        # Check if the event ID matches logsource category
        category = logsource.get('category', None)
        if category:
            try:
                return event_ids_sysmon[category] == event['System']['EventID']
            except KeyError:
                return True


    def filter_events(self, events: list) -> dict:
        # Filter the events based on the rules
        # Return the {event record id: [rule id]} dictionary
        filtered_events = {}
        for event in events:
            rule_id_list = []
            for rule in self.rules:
                if self.matches_rule(rule, event):
                    rule_id = rule.get('id', None)
                    if rule_id:
                        rule_id_list.append(rule_id)
                    else:
                        print(f"Rule ID not found for rule {rule}")
            if rule_id_list:
                filtered_events[event['System']['EventRecordID']] = rule_id_list
                
        return filtered_events




if __name__ == '__main__':
    pass