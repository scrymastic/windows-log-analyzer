

class LogAnalysis:
    def __init__(self, events: dict):
        self.events = events

        
    def count_events_by_id(self):
        # Count events based on the Event ID
        # Return a dictionary with the Event ID as the key
        # and the count of events as the value
        event_counts_by_id = {}
        for event_record_id, event_data in self.events.items():
            event_id = event_data["System"]["EventID"]
            if event_id in event_counts_by_id:
                event_counts_by_id[event_id] += 1
            else:
                event_counts_by_id[event_id] = 1
        return event_counts_by_id
    

    def count_events_by_provider(self):
        # Count events based on the Provider Name
        # Return a dictionary with the Provider Name as the key
        # and the count of events as the value
        event_counts_by_provider = {}
        for event_record_id, event_data in self.events.items():
            provider_name = event_data["System"]["Provider"]["#attributes"]["Name"]
            if provider_name in event_counts_by_provider:
                event_counts_by_provider[provider_name] += 1
            else:
                event_counts_by_provider[provider_name] = 1
        return event_counts_by_provider
    

    def get_time_range(self):
        # Get the earliest and latest event time
        # Return a tuple with the earliest and latest event time
        event_times = []
        for event_record_id, event_data in self.events.items():
            event_time = event_data["System"]["TimeCreated"]["#attributes"]["SystemTime"]
            event_times.append(event_time)
        event_times.sort()
        return event_times[0], event_times[-1]

    
    def search_events(self, keywords: list):
        # Search for events that contain the keyword in any field
        matching_events = []
        for event_record_id, event in self.events.items():
            if all(keyword in str(event) for keyword in keywords):
                matching_events.append(event_record_id)
        return matching_events
    

    def get_event(self, event_record_id: int):
        # Return the event with the specified Event Record ID
        return self.events.get(event_record_id, None)
