
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
        try:
            for key in keys:
                event = event[key]
            return event
        except (KeyError, TypeError):
            return None
    

    @staticmethod
    def assign_event_universal_id(event: EventType) -> EventType:
        event_id = str(uuid4())
        event['UniversalID'] = event_id
        return event