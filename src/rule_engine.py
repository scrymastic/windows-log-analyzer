import glob
import os
import yaml
import shutil
from pathlib import Path
from config import ROOT
from colorama import Fore, Style

RED = Fore.RED
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
CYAN = Fore.CYAN
RESET = Style.RESET_ALL


class RuleEngine:
    def __init__(self):
        # Specify the path to the legit-rules folder
        self.legit_rules_folder = Path(ROOT, "rules", "legit-rules")
        # Specify the path to the active-rules folder
        self.active_rules_folder = Path(ROOT, "rules", "active-rules")

    def check_rule(self, rule_path: str) -> bool:
        # Load the YAML rule file
        rule_file = Path(rule_path)
        with open(rule_file, 'r') as f:
            try:
                rule = yaml.safe_load(f)
            except yaml.YAMLError as e:
                print(f"{RED}[ERROR] Rule '{rule_file.name}' is not a valid YAML file.{RESET}")
                return False

        # Check if the rule has the same format as the example rule
        required_fields = [
            "title", "id", "related", "status", "description", "references", "author", "date",
            "tags", "logsource", "detection", "falsepositives", "level"
        ]

        if all(field in rule for field in required_fields):
            if isinstance(rule["title"], str) and \
                isinstance(rule["id"], str) and \
                isinstance(rule["related"], list) and \
                isinstance(rule["status"], str) and \
                isinstance(rule["description"], str) and \
                isinstance(rule["references"], list) and \
                isinstance(rule["author"], str) and \
                isinstance(rule["date"], str) and \
                isinstance(rule["tags"], list) and \
                isinstance(rule["logsource"], dict) and \
                isinstance(rule["detection"], dict) and \
                isinstance(rule["falsepositives"], list) and \
                isinstance(rule["level"], str) and \
                isinstance(rule["related"], list):
                    return True
        return False


    def add_rule(self, rule_path: str) -> bool:
        rule_file = Path(rule_path)
        if rule_file.exists() and self.check_rule(rule_path):
            # Copy the rule file to the legit-rules folder
            shutil.copy(rule_file, self.legit_rules_folder)
            print(f"{GREEN}[INFO] Rule '{rule_file.name}' added successfully.{RESET}")
            return True
        else:
            print(f"{RED}[ERROR] Rule '{rule_file.name}' added failed.{RESET}")
            return False


    def remove_rule(self, rule_file_name: str) -> bool:
        # Assuming `rule` is the name of the rule file
        rule_file = self.legit_rules_folder / f"{rule_file_name}"
        if rule_file.exists():
            # Remove the rule file from the legit-rules folder
            rule_file.unlink()
            print(f"{GREEN}[INFO] Rule '{rule_file_name}' removed successfully.{RESET}")
            return True
        else:
            print(f"{RED}[ERROR] Rule '{rule_file_name}' not found.{RESET}")
            return False


    def deploy_rule(self, rule_file_name: str) -> bool:
        # Assuming `rule` is the name of the rule file from legit-foder
        # Deploy the rule to the rule engine
        # By moving the rule from the legit-rules folder to the active-rules folder
        # As follows:
        # /active-rules/detections/{rule_id}.yml: detection, logsource, and id fields
        # /active-rules/metadata/{rule_id}.yml: other metadata
        # Get the rule file from the legit-rules folder
        rule_file = self.legit_rules_folder / f"{rule_file_name}"
        if rule_file.exists():
            print(f"{CYAN}[INFO] Deploying rule '{rule_file_name}'...{RESET}")
            # Move the rule file to the active-rules folder
            rule_content = yaml.safe_load(open(rule_file, "r"))
            # Create log source and detection file
            detection = {
                'id': rule_content['id'],
                'detection': rule_content['detection'],
                'logsource': rule_content['logsource']
            }
            with open(self.active_rules_folder / "detections" / f"{rule_content['id']}.yml", "w") as f:
                yaml.dump(detection, f)

            # Other metadata
            metadata = rule_content.copy()
            metadata.pop('detection')
            metadata.pop('logsource')
            metadata.pop('id')
            with open(self.active_rules_folder / "metadata" / f"{rule_content['id']}.yml", "w") as f:
                yaml.dump(metadata, f)

            print(f"{GREEN}[INFO] Rule '{rule_file_name}' deployed successfully.{RESET}")
            print(f"{CYAN}[INFO] Rule ID: {rule_content['id']}{RESET}")
            return True

        else:
            print(f"{RED}[ERROR] Rule '{rule_file_name}' not found.{RESET}")
            return False


    def undeploy_rule(self, rule_id: str) -> bool:
        # Undeploy the rule from the rule engine
        # By deleting the rule from the active-rules folder to the legit-rules folder

        arf = self.active_rules_folder
        if (arf / "detections" / f"{rule_id}.yml").exists() or \
            (arf / "metadata" / f"{rule_id}.yml").exists():
            # Remove the rule files from the active-rules folder
            (arf / "detections" / f"{rule_id}.yml").unlink()
            (arf / "metadata" / f"{rule_id}.yml").unlink()
            
            print(f"{GREEN}[INFO] Rule '{rule_id}' undeployed successfully.{RESET}")
            return True
        else:
            print(f"{RED}[ERROR] Rule '{rule_id}' not found.{RESET}")
            return False


    def get_active_rules(self) -> list:
        # Return the list of active rules
        # Load the rules from the /active-rules/detections folder
        yaml_files = glob.glob(os.path.join(self.active_rules_folder / "detections", "*.yml"))
        return yaml_files
    

    def get_rule(self, rule_id: str) -> dict:
        # Return the rule with the specified rule ID
        # Load the rule from the /active-rules/detections folder
        rule_detection = self.active_rules_folder / "detections" / f"{rule_id}.yml"
        rule_metadata = self.active_rules_folder / "metadata" / f"{rule_id}.yml"
        if rule_detection.exists() and rule_metadata.exists():
            with open(rule_detection, 'r') as f:
                detection = yaml.safe_load(f)
            with open(rule_metadata, 'r') as f:
                metadata = yaml.safe_load(f)
            rule = {**metadata, **detection}
            return rule


    def search_rules(self, keywords=list) -> list:
        # Return the list of rules that contain the keyword
        matching_rules = []

        # Use glob to find all YAML files in the legit-rules folder
        yaml_files = glob.glob(os.path.join(self.legit_rules_folder, "*.yml"))

        # Iterate over each YAML file
        for yaml_file in yaml_files:
            with open(yaml_file, 'r') as file:
                rule = yaml.safe_load(file)
                # Check if the keyword is present in any field of the rule
                if all(keyword in str(rule) for keyword in keywords):
                    matching_rules.append(rule["id"])

        return matching_rules
    

    def load_rules(self) -> dict:
        # Load the rules from the active-rules folder
        # Return the rules as a list of dictionaries
        rules = {}
        arf = self.active_rules_folder
        yaml_files = glob.glob(os.path.join(arf / "detections", "*.yml"))
        for yaml_file in yaml_files:
            with open(yaml_file, 'r') as file:
                rule = yaml.safe_load(file)
                rule_id = rule["id"]
                rules[rule_id] = rule
        print(f"{CYAN}[INFO] {len(rules)} rules loaded.{RESET}")
        return rules
    
    

if __name__ == "__main__":
    rule_engine = RuleEngine()
    
    # deploy all rules from legit-rules folder
    rule_folder = rule_engine.legit_rules_folder
    for rule_file in os.listdir(rule_folder):
        rule_engine.deploy_rule(rule_file)
