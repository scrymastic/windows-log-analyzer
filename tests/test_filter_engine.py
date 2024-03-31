

import yaml

# file_path = "D:\\AtSchool\\windows-log-analyzer\\rules\\legit-rules\\proc_creation_win_cmd_redirect.yml"

# def read_rule(file_path):
#     with open(file_path, 'r') as file:
#         rule = yaml.safe_load(file)
#         return rule
    
# rule = read_rule(file_path)
# print(rule["detection"])


def matches_rule(rule, event):
    # Check if all conditions in the 'and' list are satisfied
    if not matches_and_condition(rule, event):
        return False

    # If all 'and' conditions are satisfied, return True
    return True

def matches_and_condition(condition, event):
    # Check if all conditions in the 'and' list are satisfied
    for condition in condition.get('and', []):
        if not matches_condition(condition, event):
            return False

    # If all 'and' conditions are satisfied, return True
    return True

def matches_or_condition(condition, event):
    # Check if any condition in the 'or' list is satisfied
    for condition in condition.get('or', []):
        if matches_condition(condition, event):
            return True
        
def matches_condition(condition, event):
    # Extract the key and value from the condition
    key, value = next(iter(condition.items()))
    print(key, value)

    # If no 'or' condition is satisfied, return False
    return False


# Example usage:
rule = {
    'and': [
        {'EventID|==': 1},
        {'or': [
            {'OriginalFileName|==': 'Cmd.Exe'},
            {'Image|endswith': '\\cmd.exe'}
            ]
        },
        {'CommandLine|contains': '>'},
        {'CommandLine|not contains': 'C:\\Program Files (x86)\\Internet Download Manager\\IDMMsgHost.exe'},
        {'CommandLine|not contains': 'chrome-extension://'}
    ]
}

event = {
    "Provider": "Microsoft-Windows-Sysmon",
    "EventID": 1,
    "TimeCreated": "2019-07-01T00:00:00.000Z",
    "EventData": {
        "Image": "C:\\Windows\\System32\\wscript.exe\\cmd.exe",
        "Description": "Microsoft ® Windows Based Script Host",
        "Product": "Microsoft® Windows Script Host",
        "Company": "Microsoft Corporation",
        "CommandLine": "wscript.exe C:\\Users\\user\\Desktop\\malicious.vbs",
        "User": "user",
        "ParentImage": "C:\\Windows\\explorer.exe",
        "ParentCommandLine": "explorer.exe"
    }
}

if matches_rule(rule, event):
    print("Event matches the rule")
else:
    print("Event does not match the rule")



