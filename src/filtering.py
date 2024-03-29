



# Filter out suspicious events
def filter_events(event, rules):
    """
    Filter out suspicious events
    """
    print('Filtering from filtering.py')
    for rule in rules:
        # Check if the event matches the rule
        # Sample code: if event.matches(rule):
        if event.matches(rule):
            return True
    return False