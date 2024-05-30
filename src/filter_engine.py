

from src.utils.logger import logger
from src.rules.rule import RuleType, RuleMethod
from src.events.event import EventType, EventMethod
from typing import Generator, Union, Dict, List, Any
from base64 import b64decode
from ipaddress import ip_network
import re



def all_of(*args):
    return all(args) 
def any_of(*args):
    return any(args)


class FilterEngine:
    """
    A class that implements a filter engine for filtering events based on rules defined in Sigma format.
    """
    def __init__(self, rule_set: Dict[str, RuleType]):
        self._rule_set: dict = rule_set


    def match_block(self, block: Union[Dict, List], event: EventType) -> bool:
        """
        Match a block of expressions against an event.
        E.g.: selection, filter, etc.
        """
        if isinstance(block, dict):
            return all(self.match_expression(expression, value, event)
                       for expression, value in block.items())
        elif isinstance(block, list):
            return any(self.match_expression(expression, value, event)
                       for condition in block for expression, value in condition.items())
            # condition might be a string in some cases, not handled here
        else:
            raise ValueError('Unexpected value type:', block)
    

    def match_expression(self, expression: str, value: Any, event: EventType) -> bool:
        if '|' in expression:
            field, operator = expression.split('|', 1)
        else:
            field = expression
            operator = None

        if field == 'EventID':
            event_field = EventMethod.get_field(event, 'System', 'EventID')
        else:
            event_field = EventMethod.get_field(event, 'EventData', field)

        if event_field is None:
            return False
        
        if not isinstance(value, list):
            value = [value]
        
        match operator:
            case None:
                return all(event_field == val for val in value) # value has only one element
            case 'startswith':
                return any(event_field.startswith(val) for val in value)
            case 'endswith':
                return any(event_field.endswith(val) for val in value)
            case 'contains':
                return any(val in event_field for val in value)
            case 'contains|windash':
                return any(val in event_field for val in value)
            case 'contains|all':
                return all(val in event_field for val in value)
            case 'contains|all|windash':
                return all(val in event_field for val in value)
            case 'base64offset|contains':
                try:
                    event_field = b64decode(event_field).decode('utf-8')
                except ValueError as e:
                    return False
                return any(val in event_field for val in value)
            case 're':
                return any(re.match(val, event_field) for val in value)
            case 'cidr':
                return any(ip_network(val).overlaps(ip_network(event_field)) for val in value)
            
            case 'not startswith':
                return all(not event_field.startswith(val) for val in value)
            case 'not endswith':
                return all(not event_field.endswith(val) for val in value)
            case 'not contains':
                return all(val not in event_field for val in value)
            case 'not contains|all':
                return not all(val in event_field for val in value)
            case 'not re':
                return all(not re.match(val, event_field) for val in value)
            case 'not cidr':
                return all(not ip_network(val).overlaps(ip_network(event_field)) for val in value)
            
            case _:
                raise ValueError(f'Unsupported operator in expression: {expression}')
            
    
    def match_logsource(self, logsource: Dict, event: EventType) -> bool:
        event_id = EventMethod.get_field(event, 'System', 'EventID')
        if not isinstance(event_id, int):
            # logging.error(f"EventID is not an integer: {event_id}")
            return False
        if expected_category := RuleMethod.get_expected_category(event_id):
            return expected_category == logsource.get('category', None)
        return True


    def match_rule(self, rule_id: str, rule: RuleType, event: EventType) -> bool:
        # The para 'event' is for debug purpose
        try:
            eval_expr = RuleMethod.get_field(rule, 'detection', 'evaluation')
            return eval(eval_expr)
        except Exception as e:
            logger.error(f"Error evaluating rule: {e}, id: {rule_id}, event: {event}")
            return False


    def match_rules(self, event: EventType) -> List[str]:
        matched_rules = []
        for rule_id, rule in self._rule_set.items():
            if self.match_rule(rule_id, rule, event):
                matched_rules.append(rule_id)
        return matched_rules
    

    def filter_events(self, events: EventType) -> Dict[str, List[str]]:
        if not events:
            return []
        filtered_events = {}
        for event in events:
            if not EventMethod.is_valid_event(event):
                continue
            matched_rules = self.match_rules(event)
            if matched_rules:
                filtered_events.update({EventMethod.get_field(event, 'UniversalID'): matched_rules})
        return filtered_events
    

    def filter_events_yield(self, events: EventType) -> Generator[Dict[str, List[str]], None, None]:
        if not events:
            return {}
        for event in events:
            if not EventMethod.is_valid_event(event):
                continue
            matched_rules = self.match_rules(event)
            if matched_rules:
                yield {EventMethod.get_field(event, 'UniversalID'): matched_rules}


    @property
    def rule_set(self) -> Dict[str, RuleType]:
        return self._rule_set
    
    @rule_set.setter
    def rule_set(self, rule_set: Dict[str, RuleType]) -> None:
        self._rule_set = rule_set


if __name__ == '__main__':
    pass