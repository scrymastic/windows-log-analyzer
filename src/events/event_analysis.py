
from src.events.event import EventType, EventMethod
from src.config import LOCAL_TIMEZONE
from typing import Dict, List, Tuple
from datetime import datetime, timedelta
import re


class EventAnalysis:
    """
    Class to perform analysis on a list of events.
    """
    def __init__(self, events: List[EventType]):
        self._events = events
        # self.event_frame = pd.DataFrame(events) for further analysis
        
    def count_events_by_id(self) -> Dict[int, int]:
        event_counts_by_id = {}
        for event in self._events:
            event_id = str(EventMethod.get_field(event, "System", "EventID"))
            if event_id in event_counts_by_id:
                event_counts_by_id[event_id] += 1
            else:
                event_counts_by_id[event_id] = 1
        return event_counts_by_id
    

    def count_events_by_provider(self) -> Dict[str, int]:
        event_counts_by_provider = {}
        for event in self._events:
            provider = EventMethod.get_field(event, "System", "Provider", "#attributes", "Name")
            if provider in event_counts_by_provider:
                event_counts_by_provider[provider] += 1
            else:
                event_counts_by_provider[provider] = 1
        return event_counts_by_provider
    

    def get_time_range(self) -> Tuple:
        # Get the earliest and latest event time
        event_times = [EventMethod.get_field(event, "System", "TimeCreated", "#attributes", "SystemTime") for event in self._events]
        return min(event_times), max(event_times)
    

    def get_events_by_time_range(self, start_time: str, end_time: str, local_time_zone: float = LOCAL_TIMEZONE) -> List[EventType]:
        # Get events that fall within the specified time range
        # Check if the time is in the correct format
        if not re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{1,5}Z", start_time):
            raise ValueError("Invalid start time format. Use 'YYYY-MM-DDTHH:MM:SS.sssssZ'")
        if not re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{1,5}Z", end_time):
            raise ValueError("Invalid end time format. Use 'YYYY-MM-DDTHH:MM:SS.sssssZ'")
        # Convert the time to utc
        start_time = datetime.strptime(start_time, "%Y-%m-%dT%H:%M:%S.%fZ") - timedelta(hours=local_time_zone)
        end_time = datetime.strptime(end_time, "%Y-%m-%dT%H:%M:%S.%fZ") - timedelta(hours=local_time_zone)
        matching_events = []
        for event in self._events:
            event_time = EventMethod.get_field(event, "System", "TimeCreated", "#attributes", "SystemTime")
            if start_time <= event_time <= end_time:
                matching_events.append(event)
        return matching_events


    def get_events_by_order_range(self, start_order: int, end_order: int) -> List[EventType]:
        # Get events that fall within the specified order range
        return self._events[start_order:end_order]
    

    def get_events_by_event_id(self, event_id: int) -> List[EventType]:
        # Get events that match the specified event ID
        matching_events = []
        for event in self._events:
            if EventMethod.get_field(event, "System", "EventID") == event_id:
                matching_events.append(event)
        return matching_events

    
    def get_events_by_keywords(self, keywords: List[str]) -> List[EventType]:
        # Search for events that contain the keywords
        keywords = [keyword.lower() for keyword in keywords]
        matching_events = []
        for event in self._events:
            if all(keyword in str(event).lower() for keyword in keywords):
                matching_events.append(event)
        return matching_events
    

    def get_event_by_universal_id(self, universal_id: str) -> EventType:
        # Search for events that contain the keyword in any field
        for event in self._events:
            if EventMethod.get_field(event, "UniversalID") == universal_id:
                return event
        return None
    

    @property
    def events(self) -> List[EventType]:
        return self._events

    @events.setter
    def events(self, events: List[EventType]) -> None:
        self._events = events



if __name__ == "__main__":
    from logs.log_parser import LogParser
    log_parser = LogParser()
    events = log_parser.parse_log_file(r'D:\AtSchool\windows-log-analyzer\sample-logs\Execution\rogue_msi_url_1040_1042.evtx')
    log_analysis = EventAnalysis(events)
    print(log_analysis.count_events_by_id())
    print(log_analysis.count_events_by_provider())
    print(log_analysis.get_time_range())
    print(log_analysis.get_events_by_time_range("2019-10-31T00:00:00.000Z", "2022-10-31T23:59:59.999Z"))