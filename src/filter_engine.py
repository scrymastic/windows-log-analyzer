
import regex


def ANY(*args):
    return any(args)

def ALL(*args):
    return all(args)

class FilterEngine:
    def __init__(self, rules):
        self.rules = rules


    def matches_rule(self, rule, event: dict) -> bool:
        logsource = rule.get('logsource', None)
        if not logsource:
            print(f"Logsource not found in rule {rule}")
            return False
        if not self.match_event_id(logsource, event):
            return False
        
        # detection
        detection = rule.get('detection', None)
        # condition block and at least one condition
        if len(detection) < 2:
            print(f"Invalid rule '{rule}'")
            return False
        
        # Convert to the new format, list of dictionaries -> dictionary
        detection = {key: value for block in detection for key, value in block.items()}

        
        # Extract the condition block and conditions
        condition = detection.get('condition', None)
        if not condition:
            print(f"Condition not found in rule {rule}")
            return False
        

        exclude_words = {'1', 'not', 'and', 'all', 'or', '(', ')', 'of', ''}
        block_keys = [word for word in regex.split(r'\s+|\(|\)', condition) if word not in exclude_words]
        matched_keys = {block_key: [] for block_key in block_keys}

        for key, value in detection.items():
            matched_key = self.check_block_key(block_keys, key)
            if matched_key:
                matched_keys[matched_key].append(key)
            else:
                if key != 'condition':
                    print(f"Invalid key '{key}' in rule {rule}")
                    print(f"Block keys: {block_keys}")
                    print(f"Matched keys: {matched_keys}")
                    return False
        
        # Construct the condition query
        matched_keys = dict(sorted(matched_keys.items(), key=lambda item: -len(item[0])))
        for key, values in matched_keys.items():
            # process escaped characters
            values = [value.replace('\\', '') for value in values]
            query = ', '.join([f"self.matches_and_block(detection['{value}'][0]['and'], event)" for value in values])
            if condition.startswith(f"{key} "):
                condition = condition.replace(f"{key} ", f"({query}) ")
            elif condition.endswith(f" {key}"):
                condition = condition.replace(f" {key}", f" ({query})")
            elif condition.find(f" {key} ") != -1:
                condition = condition.replace(f" {key} ", f" ({query}) ")
            elif condition.find(f" {key})") != -1:
                condition = condition.replace(f" {key}", f" ({query})")
            elif condition.find(f"({key} ") != -1:
                condition = condition.replace(f"{key} ", f"({query}) ")
            elif condition == key:
                condition = f"({query})"
            else:
                print(f"Unexpected condition: {condition}")
                return False

        condition = condition.replace('all of ', 'ALL').replace('1 of ', 'ANY')

        try:
            return eval(condition)
        except Exception as e:
            print(f"Error evaluating condition: {e}")
            return False


    def check_block_key(self, block_keys: list, key: str) -> str:
        # Check if the key is covered by the fields
        # For example, if the fields are ['selection', 'selection_*', 'filter', 'filter_*']
        for block_key in block_keys:
            target = block_key.split('*')
            if len(target) == 2:
                if key.startswith(target[0]):
                    return block_key
            elif key == block_key:
                return block_key
        return None


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
            if '.' in field_value and '.' in value:
                return IPv4Address(field_value) in IPv4Network(value)
            elif ':' in field_value and ':' in value:
                return IPv6Address(field_value) in IPv6Network(value)
            else:
                return False
        elif operator == 'not cidr':
            from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network
            if '.' in field_value and '.' in value:
                return IPv4Address(field_value) not in IPv4Network(value)
            elif ':' in field_value and ':' in value:
                return IPv6Address(field_value) not in IPv6Network(value)
            else:
                return False
        else:
            print(f"Invalid operator '{operator}, key: {key}, value: {value}'")
            return False


    def get_field_value(self, event, field):
        # Extract the field value from the event data
        if field == 'EventID':
            if not event['System']:
                return None
            return event['System']['EventID']
        else:
            if not event['EventData']:
                return None
            return event['EventData'].get(field, None)
        
    
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


    def filter_events(self, events: dict) -> dict:
        # Filter the events based on the rules
        # Return the {event record id: [rule id]} dictionary
        if not events:
            print("No events to filter")
            return {}
        num_events = len(events)
        processed_events = 0
        filtered_events = {}
        for event_id, event in events.items():
            rule_id_list = []
            for rule_id, rule in self.rules.items():
                if self.matches_rule(rule, event):
                    rule_id_list.append(rule_id)
            if rule_id_list:
                filtered_events[event_id] = rule_id_list
            processed_events += 1
            print(f"\rProcessed {processed_events}/{num_events} events", end='')
                
        return filtered_events




if __name__ == '__main__':
    pass