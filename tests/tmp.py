
# import yaml


# with open('rules/legit-rules/proc_creation_win_cmd_redirect.yml', 'r') as f:
#     data = yaml.load(f, Loader=yaml.FullLoader)

# print(data["detection"])

import ipaddress
condition = {'DestinationIp|cidr': '1::/64'}
event = {'DestinationIp': '1::1'}
# DestinationIp|cidr: '::1/128'
# check if the ip address is in the range
# If ipv4
field_value = event['DestinationIp']
value = condition['DestinationIp|cidr']
print(ipaddress.IPv6Address(field_value))
print(ipaddress.IPv6Network(value))
print(ipaddress.IPv6Address(field_value) in ipaddress.IPv6Network(value))