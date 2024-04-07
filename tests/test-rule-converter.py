

import yaml

rule_file = "D:\AtSchool\windows-log-analyzer\\rules\sigma-rules\process_creation\proc_creation_win_appvlp_uncommon_child_process.yml"

with open(rule_file, 'r') as file:
    rule = yaml.safe_load(file)

print(rule["detection"])