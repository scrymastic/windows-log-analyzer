
from typing import TypedDict, Any
from uuid import uuid4


class EventType(TypedDict):
    """
    Type definition for an event.
    """
    System: dict
    EventData: dict
    UniversalID: str


class EventMethod:

    @staticmethod
    def is_valid_event(event: EventType) -> bool:
        # Check if the event has the required fields
        return True
    

    @staticmethod
    def get_field(event: EventType, *keys) -> Any:
        # Useful for getting nested fields from an event
        try:
            for key in keys:
                event = event[key]
            return event
        except (KeyError, TypeError):
            return None
    

    @staticmethod
    def set_field(event: EventType, value: Any, *keys) -> EventType:
        # Useful for setting nested fields in an event
        try:
            for key in keys[:-1]:
                event = event[key]
            event[keys[-1]] = value
            return event
        except (KeyError, TypeError):
            return None
    

    @staticmethod
    def assign_event_universal_id(event: EventType) -> EventType:
        event_id = str(uuid4())
        event['UniversalID'] = event_id
        return event