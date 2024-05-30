

from src.config import ROOT
from src.utils.logger import logger
from src.rules.rule import RuleType, RuleMethod
from typing import Dict, List
from pathlib import Path
import shutil


class RuleEngine:
    _rule_folder: Path = ROOT / "rules"
    _rule_index = {}

    def __init__(self, rule_set: Dict[str, RuleType]):
        self._rule_set: dict = rule_set


    def add_rule(self, rule_path: Path) -> bool:
        if self.is_valid_rule(rule_path):   # And rule id is unique
            # Copy the rule file to the rules folder
            shutil.copy(rule_path, RuleEngine._rule_folder / rule_path.name)
            logger.info(f"Rule {rule_path.name} added successfully.")
            return True
        else:
            logger.error(f"Rule {rule_path.name} is not valid.")
            return False


    def remove_rule(self, rule_path: Path) -> bool:
        if rule_path.exists():
            rule_path.unlink()
            logger.info(f"Rule {rule_path.name} removed successfully.")
            return True
        else:
            logger.error(f"Rule {rule_path.name} not found.")
            return False


    def deploy_rule(self, rule_path: Path) -> str:
        # Check if the rule is in the rules folder
        try:
            rule_path.relative_to(self._rule_folder)
        except ValueError:
            logger.error(f"Rule {rule_path.name} not found in the rules folder.")
            return None
        
        # Update the rule_set with the new rule
        if rule := RuleMethod.load_rule_filter(rule_path):
            self._rule_set.update(rule)
            rule_id = list(rule.keys())[0]
            logger.info(f"Rule {rule_path.name} deployed successfully with ID {rule_id}.")
            return rule_id
        else:
            logger.error(f"Rule {rule_path.name} could not be deployed.")
            return None


    def undeploy_rule(self, rule_id: str) -> str:
        # Remove the rule from the rule_set
        if rule := self._rule_set.pop(rule_id, None):
            logger.info(f"Rule {rule_id} undeployed successfully.")
            return rule_id
        else:
            logger.error(f"Rule {rule_id} could not be undeployed.")
            return None
        
    
    def load_all_rules(self, rule_folder: Path = None) -> None:
        if not rule_folder:
            rule_folder = self._rule_folder
        # Load all rules from the rules folder
        for rule_file in rule_folder.rglob("*.yml"):
            if rule := RuleMethod.load_rule_filter(rule_file):
                self._rule_set.update(rule)
        

    @classmethod
    def build_rule_index(cls) -> None:
        # Build an index for the rules
        for rule_file in cls._rule_folder.rglob("*.yml"):
            if rule := RuleMethod.load_rule_filter(rule_file):
                rule_id = list(rule.keys())[0]
                cls._rule_index[rule_id] = rule_file.relative_to(cls._rule_folder)


    @classmethod
    def get_rule_path_by_id(cls, rule_id: str) -> Path:
        if rule_file_name := cls._rule_index.get(rule_id, None):
            return cls._rule_folder / rule_file_name
        else:
            return None
    

    @classmethod
    def get_rule_content_by_id(cls, rule_id: str) -> RuleType:
        if rule_path := cls.get_rule_path_by_id(rule_id):
            return RuleMethod.load_rule_full(rule_path)
        else:
            return None

    
    @classmethod
    def search_rules(cls, keywords: List[str]) -> List[Path]:
        # Traverse the rules folder to find the rules that contain the specified keywords
        rules = []
        for rule_file in cls._rule_folder.rglob("*.yml"):
            if all(keyword.lower() in rule_file.name.lower() for keyword in keywords):
                rules.append(rule_file)
        return rules
        

    @property
    def rule_set(self) -> Dict[str, RuleType]:
        return self._rule_set
    

    @rule_set.setter
    def set_rule_set(self, rule_set: Dict[str, RuleType]) -> None:
        self._rule_set = rule_set
        
        
    
if __name__ == "__main__":
    pass