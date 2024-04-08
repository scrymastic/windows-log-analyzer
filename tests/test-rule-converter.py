
import yaml
import regex
from pathlib import Path

class RuleConverter:
    def __init__(self):
        # self.legit_rules_folder = Path(ROOT, "rules", "legit-rules")
        pass


    def convert(self, rule_path: str) -> bool:
        rule_file = Path(rule_path)
        if not rule_file.exists():
            print(f"Rule file '{rule_file.name}' does not exist.")
            return False
        
        with open(rule_file, 'r') as f:
            try:
                rule = yaml.safe_load(f)
            except yaml.YAMLError as e:
                print(f"Error loading YAML file: {e}")
                return False
            
        # convert the rule['detection'] block
        detection = rule.get('detection', {})
        if detection:
            converted_detection = self.convert_detection_block(detection)
            converted_detection = [{'and': converted_detection}]

            # try to dump
            print(yaml.dump(converted_detection))

    
    def convert_detection_block(self, detection): 
        conditions = detection.get('condition', '')
        if not self.handle_condition(conditions):
            raise ValueError(f'Unsupported condition: {conditions}')
            
        converted_detection = []
        for key, value in detection.items():
            if key == 'condition':
                continue
            if isinstance(value, dict):
                converted_block = self.convert_and_block(value)
            elif isinstance(value, list):
                converted_block = self.convert_or_block(value)
            else:
                raise ValueError('Unexpected value type:', value)
            
            if 'selection' in key:
                converted_detection.extend(converted_block)
            elif 'filter_' in key:
                converted_detection.extend(self.invert_conditions(converted_block))

        return converted_detection
    

    def handle_condition(self, condition):
        if regex.match(r'^(?:all of )?selection(?:_[^\s]*)?(?: (?:and not 1 of filter_[^\s]+))*', condition):
            return True
        else:
            return False
        

    def convert_expression(self, expression):
        mapping = {
            'contains': 'contains',
            'endswith': 'endswith',
            'startswith': 'startswith',
            're': 'matches',
            'cidr': 'cidr',
            'not contains': 'not contains',
            'not endswith': 'not endswith',
            'not startswith': 'not startswith',
            'not re': 'not matches',
            'not cidr': 'not cidr',
            'contains|all': 'contains',
        }
        
        if '|' in expression:
            field, operator = expression.split('|', 1)
            operator = mapping.get(operator)
        else:
            field = expression
            operator = '=='

        return f"{field}|{operator}"
            

    def convert_and_block(self, block):
    # converted_block = {'and': []}
        converted_block = []
        for key, value in block.items():
            if isinstance(value, list):
                if key.endswith('|contains|all'):
                    expression = self.convert_expression(key)
                    sub_block = []
                    for item in value:
                        if isinstance(item, str):
                            sub_block.append({expression: item})
                        else:
                            raise ValueError('Unexpected value type:', item)
                    converted_block.extend(sub_block)           
                else:
                    expression = self.convert_expression(key)
                    sub_block = {'or': []}
                    for item in value:
                        if isinstance(item, str):
                            sub_block['or'].append({expression: item})
                        elif isinstance(item, int):
                            sub_block['or'].append({expression: item})
                        else:
                            raise ValueError('Unexpected value type:', item)
                    converted_block.append(sub_block)

            elif isinstance(value, str):
                converted_block.append({self.convert_expression(key): value})
            elif isinstance(value, int):
                converted_block.append({self.convert_expression(key): value})
            else:
                raise ValueError('Unexpected value type:', value)

        return converted_block


    def convert_or_block(self, block):
        converted_block = {'or': []}
        for value in block:
            if isinstance(value, dict):
                converted_block['or'].extend(self.convert_and_block(value))
            else:
                raise ValueError('Unexpected value type:', value)
        return [converted_block]
    

    def invert_conditions(self, conditions: list) -> list:
        inverted_conditions = []
        conditions = conditions[0].get('or', [])
        if not conditions:
            return inverted_conditions
        for condition in conditions:
            for key, value in condition.items():
                field, operator = key.split('|', 1)
                if operator == '==':
                    operator = '!=='
                elif operator == '!=':
                    operator = '=='
                else:
                    if 'not' not in operator:
                        operator = f'not {operator}'
                    else:
                        operator = operator.replace('not ', '')
                inverted_conditions.append({f'{field}|{operator}': value})

        return inverted_conditions


rule_path = "D:\AtSchool\windows-log-analyzer\\rules\sigma-rules\process_creation\proc_creation_win_addinutil_uncommon_child_process.yml"
rule_converter = RuleConverter()
rule_converter.convert(rule_path)