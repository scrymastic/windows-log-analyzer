import glob
import os
import yaml
import shutil
from pathlib import Path
from config import ROOT


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
                print(f"Error loading YAML file: {e}")
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
            print(f"Rule '{rule_file.name}' added successfully.")
            return True
        else:
            print(f"Rule file '{rule_file.name}' does not exist.")
            return False


    def remove_rule(self, rule_file_name: str) -> bool:
        # Assuming `rule` is the name of the rule file
        rule_file = self.legit_rules_folder / f"{rule_file_name}"
        if rule_file.exists():
            # Remove the rule file from the legit-rules folder
            rule_file.unlink()
            print(f"Rule '{rule_file_name}' removed successfully.")
            return True
        else:
            print(f"Rule '{rule_file_name}' does not exist in legit-folder")
            return False


    def deploy_rule(self, rule_file_name: str) -> bool:
        # Assuming `rule` is the name of the rule file from legit-foder

        # Deploy the rule to the rule engine
        # By moving the rule from the legit-rules folder to the active-rules folder
        # As follows:
        # /active-rules/detections/{rule_id}.yml: detection
        # /active-rules/headers/{rule_id}.yml: title
        # /active-rules/metadata/{rule_id}.yml: add filename field, other metadata

        # Get the rule file from the legit-rules folder
        rule_file = self.legit_rules_folder / f"{rule_file_name}"
        if rule_file.exists():
            # Move the rule file to the active-rules folder
            rule_content = yaml.safe_load(open(rule_file, "r"))
            # Create log source and detection file
            log_source_detection = {
                "id": rule_content["id"],
                "detection": rule_content["detection"]
            }
            with open(self.active_rules_folder / "detections" / f"{rule_content["id"]}.yml", "w") as f:
                yaml.dump(log_source_detection, f)

            # Create headers file
            headers = {
                "title": rule_content["title"]
            }
            with open(self.active_rules_folder / "headers" / f"{rule_content["id"]}.yml", "w") as f:
                yaml.dump(headers, f)

            # Create metadata file
            metadata = {
                "filename": rule_file_name,
                "related": rule_content["related"],
                "status": rule_content["status"],
                "description": rule_content["description"],
                "references": rule_content["references"],
                "author": rule_content["author"],
                "date": rule_content["date"],
                "modified": rule_content["modified"],
                "tags": rule_content["tags"],
                "logsource": rule_content["logsource"],
                "falsepositives": rule_content["falsepositives"],
                "level": rule_content["level"]
            }
            with open(self.active_rules_folder / "metadata" / f"{rule_content["id"]}.yml", "w") as f:
                yaml.dump(metadata, f)

            print(f"Rule file '{rule_file_name}' deployed successfully.")
            print(f"Rule ID: {rule_content['id']}")
            return True

        else:
            print(f"Rule file '{rule_file_name}' does not exist in legit-folder")
            return False


    def undeploy_rule(self, rule_id: str) -> bool:
        # Undeploy the rule from the rule engine
        # By deleting the rule from the active-rules folder to the legit-rules folder

        arf = self.active_rules_folder
        if (arf / "detections" / f"{rule_id}.yml").exists() or \
            (arf / "headers" / f"{rule_id}.yml").exists() or \
            (arf / "metadata" / f"{rule_id}.yml").exists():
            # Remove the rule files from the active-rules folder
            (arf / "detections" / f"{rule_id}.yml").unlink()
            (arf / "headers" / f"{rule_id}.yml").unlink()
            (arf / "metadata" / f"{rule_id}.yml").unlink()
            
            print(f"Rule '{rule_id}' un-deployed and removed successfully.")
            return True
        else:
            print(f"Rule '{rule_id}' is not deployed in the active-rules folder.")
            return False


    def get_active_rules(self) -> list:
        # Return the list of active rules
        # Load the rules from the /active-rules/detections folder
        yaml_files = glob.glob(os.path.join(self.active_rules_folder / "detections", "*.yml"))
        return yaml_files


    def search_rules(self, keyword: str) -> list:
        # Return the list of rules that contain the keyword

        matching_rules = []

        # Use glob to find all YAML files in the legit-rules folder
        yaml_files = glob.glob(os.path.join(self.legit_rules_folder, "*.yml"))

        # Iterate over each YAML file
        for yaml_file in yaml_files:
            with open(yaml_file, 'r') as file:
                rule = yaml.safe_load(file)
                # Check if the keyword is present in any field of the rule
                if (keyword in str(value) for value in rule.values()):
                    matching_rules.append(rule["id"])

        return matching_rules
    

    def load_rules(self) -> list:
        # Load the rules from the active-rules folder
        # Return the rules as a list of dictionaries
        rules = []
        arf = self.active_rules_folder
        yaml_files = glob.glob(os.path.join(arf / "detections", "*.yml"))
        for yaml_file in yaml_files:
            with open(yaml_file, 'r') as file:
                rule = yaml.safe_load(file)
                rules.append(rule)
        return rules
    
    

if __name__ == "__main__":
    re = RuleEngine()
    # print(re.check_rule(re,"D:\\windows-log-analyzer\\format\\rules\\id1-process-creation-after.yml"))
    # re.add_rule("D:\\windows-log-analyzer\\format\\rules\\id1-process-creation-after.yml")
    # re.remove_rule("id1-process-creation-after.yml")
    re.deploy_rule("proc_creation_win_cmd_redirect.yml")
    # re.undeploy_rule("4f4eaa9f-5ad4-410c-a4be-bc6132b0175a")
    print(re.get_active_rules())
    print(re.search_rules("CMD SHELL"))
