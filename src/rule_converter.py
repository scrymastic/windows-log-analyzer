
import yaml
import regex
from pathlib import Path
from config import ROOT
from colorama import Fore, Style

RED = Fore.RED
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
CYAN = Fore.CYAN
RESET = Style.RESET_ALL


class RuleConverter:
    def __init__(self):
        self.legit_rules_folder = Path(ROOT, "rules", "legit-rules")
        pass

    
    def convert_folder(self, folder_path: str) -> bool:
        folder = Path(folder_path)
        # check if the folder exists and is a directory
        if not folder.exists() or not folder.is_dir():
            print(f"{RED}[ERROR] Folder '{folder.name}' not found.{RESET}")
            return False

        print(f"{CYAN}[INFO] Converting rules in folder '{folder.name}'...{RESET}")
        total = 0
        success = 0
        failed = []
        for rule_file in folder.rglob('*.yml'):
            total += 1
            if self.convert_rule(rule_file):
                success += 1
            else:
                failed.append(rule_file.name)

        print(f"\n{CYAN}[INFO] Conversion completed.{RESET}")
        print(f"Total rules: {total}")
        print(f"{GREEN}Converted rules: {success}, {round(success/total*100, 2)}%{RESET}")
        print(f"{RED}Failed rules: {len(failed)}, {round(len(failed)/total*100, 2)}%{RESET}")
        for rule in failed:
            print(f"{RED}[ERROR] Rule '{rule}' failed to convert.{RESET}")

        return True
    

    def convert_rule(self, rule_path: str) -> bool:
        rule_file = Path(rule_path)
        if not rule_file.exists():
            print(f"{RED}[ERROR] Rule file '{rule_file.name}' not found.{RESET}")
            return False
        
        print(f"{CYAN}[INFO] Converting rule '{rule_file.name}'...{RESET}")

        with open(rule_file, 'r', encoding='utf-8') as f:
            try:
                rule = yaml.safe_load(f)
            except Exception as e:
                print(e)
                print(f"{RED}[ERROR] Cannot load rule '{rule_file.name}': {e}{RESET}")
                return False
            
        # convert the rule['detection'] block
        detection = rule.get('detection', {})
        if detection:
            try:
                converted_detection = self.convert_detection_block(detection)
            except Exception as e:
                print(e)
                print(f"{RED}[ERROR] Cannot convert rule '{rule_file.name}'{RESET}")
                return False
            converted_detection = [{'and': converted_detection}]
            
            # try to dump to file
            converted_rule = rule.copy()
            converted_rule['detection'] = converted_detection
            converted_rule_path = Path(self.legit_rules_folder, rule_file.name)
            with open(converted_rule_path, 'w') as f:
                yaml.dump(converted_rule, f, sort_keys=False)
                print(f"{GREEN}[SUCCESS] Rule '{rule_file.name}' converted successfully.{RESET}")
                return True
        else:
            print(f"Rule '{rule_file.name}' has no detection block.")
            return False


    def convert_detection_block(self, detection): 
        conditions = detection.get('condition', '')
        
        can_convert = self.handle_condition(conditions)
        if can_convert == 0:
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
            if can_convert == 1:
                if 'selection' in key:
                    converted_detection.extend(converted_block)
                elif 'filter_' in key:
                    converted_detection.extend(self.invert_conditions(converted_block))

            elif can_convert == 2:
                if 'selection' in key:
                    converted_detection.extend([{'or': converted_block}])
                elif 'filter_' in key:
                    converted_detection.extend(converted_block)

        return converted_detection
    

    def handle_condition(self, condition):
        if regex.match(r'^(?:all of )?selection(?:_[^\s]*)?(?: (?:and not 1 of filter_[^\s]+))*', condition) or \
            regex.match(r'^not 1 of filter_[^\s]+(?: (?:and not 1 of filter_[^\s]+))*', condition) or \
            regex.match(r'^(?:all of )?selection(?:_[^\s]*)? and not filter(?:_[^\s]*)?', condition):
            return 1
        elif regex.match(r'^1 of selection(?:_[^\s]*)?(?: (?:and not 1 of filter_[^\s]+))*', condition) or \
            regex.match(r'^1 of selection(?:_[^\s]*)? and not filter(?:_[^\s]*)?', condition):
            return 2
        else:
            return 0
        

    def convert_expression(self, expression):
        if '|' in expression:
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
            field, operator = expression.split('|', 1)
            operator = mapping.get(operator, None)
            if operator is None:
                raise ValueError(f'Unsupported operator: {operator}')
        else:
            field = expression
            operator = '=='

        return f"{field}|{operator}"
            

    def convert_and_block(self, block) -> list:
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


    def convert_or_block(self, block) -> list:
        converted_block = {'or': []}
        for value in block:
            if isinstance(value, dict):
                converted_block['or'].extend(self.convert_and_block(value))
            else:
                raise ValueError('Unexpected value type:', value)
        return [converted_block]
    

    def invert_conditions(self, conditions: list) -> list:
        inverted_conditions = []
        
        is_or = False
        block_conditions = conditions[0].get('or', [])
        if block_conditions:
            is_or = True
        else:
            block_conditions = conditions
        for condition in block_conditions:
            for key, value in condition.items():
                try:
                    field, operator = key.split('|', 1)
                except ValueError:
                    raise ValueError(f'Invalid condition to invert: {key}')
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
        
        if is_or:
            return inverted_conditions
        else:
            return [{'or': inverted_conditions}]
    

if __name__ == '__main__':
    sigma_rule_folder = Path(ROOT, "rules", "sigma-rules")
    rule_converter = RuleConverter()
    rule_converter.convert_folder(sigma_rule_folder)