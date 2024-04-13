
import yaml
import regex
from pathlib import Path
from config import *



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
        converted_detection = []
        for key, value in detection.items():
            if key == 'condition':
                converted_detection.extend([{key: value}])
                continue
            if isinstance(value, dict):
                converted_block = self.convert_and_block(value)
            elif isinstance(value, list):
                converted_block = self.convert_or_block(value)
            else:
                raise ValueError('Unexpected value type:', value)
                        
            if len(converted_block) == 1 and converted_block[0].keys() == {'and'}:
                pass
            else:
                converted_block = [{'and': converted_block}]
                
            converted_detection.extend([{key: converted_block}])

        return converted_detection
    

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
                raise ValueError(f'Unsupported operator in expression: {expression}')
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

        return [{'and': converted_block}] if len(converted_block) > 1 else converted_block


    def convert_or_block(self, block) -> list:
        converted_block = []
        for value in block:
            if isinstance(value, dict):
                converted_block.extend(self.convert_and_block(value))
            else:
                raise ValueError('Unexpected value type:', value)
        return [{'or': converted_block}]
    


if __name__ == '__main__':
    sigma_rule = Path(ROOT, "rules", "sigma-rules")#, "registry", "registry_add") #, "registry_add_persistence_disk_cleanup_handler_entry.yml")
    rule_converter = RuleConverter()
    rule_converter.convert_folder(sigma_rule)