
import yaml


with open('rules/legit-rules/proc_creation_win_cmd_redirect.yml', 'r') as f:
    data = yaml.load(f, Loader=yaml.FullLoader)

print(data["detection"])