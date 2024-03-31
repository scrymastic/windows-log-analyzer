
import regex

class EngineFilter:
    def __init__(self, rules):
        self.rules = rules


    def matches_rule(self, rule, event):
        # ignore logsource for now
        logsource = rule.get('logsource', None)
        # detection
        rule = rule.get('detection', None)
        # Check if all conditions in the 'and' list are satisfied
        if not self.matches_and_block(rule['and'], event):
            return False
        return True


    def matches_and_block(self, block, event):
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

        # Handle 'and' or 'or' block
        if len(condition) == 1:
            key = next(iter(condition))
            if key == 'and':
                return self.matches_and_block(condition[key], event)
            elif key == 'or':
                return self.matches_or_block(condition[key], event)

        # Extract the key and value from the condition
        key, value = next(iter(condition.items()))
        field, operator = key.split('|')

        # Extract the field value from the event data
        field_value = self.get_field_value(event, field)
        if field_value is None:
            return False
        # Perform the comparison based on the operator
        if operator == '==':
            return field_value == value
        elif operator == '!=':
            return field_value != value
        elif operator == 'contains':
            return value in field_value
        elif operator == 'not contains':
            return value not in field_value
        elif operator == 'startswith':
            return field_value.startswith(value)
        elif operator == 'endswith':
            return field_value.endswith(value)
        elif operator == 'matches':
            return regex.match(value, field_value)
        elif operator == 'not matches':
            return not regex.match(value, field_value)
        else:
            print(f"Invalid operator '{operator}'")
            return False


    def get_field_value(self, event, field):
        # Extract the field value from the event data
        if field == 'EventID':
            return event.get(field, None)
        else:
            event_data = event.get('EventData', {})
            return event_data.get(field, None)


    def filter_events(self, events):
        # Filter the events based on the rules
        # Return the {event id: rule id list} dictionary
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
                filtered_events[event['id']] = rule_id_list
                
        return filtered_events

    


if __name__ == '__main__':
    pass