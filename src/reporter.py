

"""""
class Reporter:
    def __init__(self):
        pass

    def report(self, event, rule_id):
        # Report the event to the rule_id
        # Get the rule title from /active-rules/headers/{rule_id}.yml
        # Get the rule metadata from /active-rules/metadata/{rule_id}.yml
        pass"""

import yaml

class Reporter:
    def __init__(self):
        pass

    def report(self, event, rule_id):
        # Fetch the rule title and metadata
        with open(f'active-rules/headers/{rule_id}.yml', 'r') as file:
            rule_header = yaml.safe_load(file)

        with open(f'active-rules/metadata/{rule_id}.yml', 'r') as file:
            rule_metadata = yaml.safe_load(file)

        # Print the report
        print("\n" + "=" * 50)
        print(f"Event: {event}")
        print("-" * 50)
        print(f"Rule ID: {rule_id}")
        print(f"Rule Title: {rule_header['title']}")
        print(f"Rule Metadata: {rule_metadata}")
        print("=" * 50 + "\n")