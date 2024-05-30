

from utils.logger import logger
from typing import TypedDict, Dict, Any
from pathlib import Path
import yaml
import re


class RuleType(TypedDict):
    """
    Type definition for a rule.
    Fields include, but not limited to: id, title, description, level, tags, detection, logsource
    """
    id: str
    detection: dict
    logsource: dict


class RuleMethod:
    _categories_mapping: dict = {
        1: "process_creation",
        2: "file_change",
        3: "network_connection",
        4: "sysmon_status",
        5: "process_termination",
        6: "driver_load",
        7: "image_load",
        8: "create_remote_thread",
        9: "raw_access_thread",
        10: "process_access",
        11: "file_event",
        12: "registry_add",
        13: "registry_delete",
        14: "registry_set",
        15: "create_stream_hash",
        17: "pipe_created",
        19: "wmi_event",
        22: "dns_query",
        23: "file_delete",
        24: "clipboard_change",
        25: "process_tampering",
        26: "file_delete_detected",
        27: "file_block_executable",
        28: "file_block_shredding",
        29: "file_executable_detected",
        255: "sysmon_error",
        4104: "ps_script"
    }
            
    @staticmethod
    def is_valid_rule(rule_path: Path, logger_enabled: bool = False) -> bool:
        if not rule_path.exists():
            return False
        with open(rule_path, 'r', encoding='utf-8') as f:
            try:
                rule = yaml.safe_load(f)
            except Exception as e:
                if logger_enabled:
                    logger.error(f"Falied to load rule {rule_path.name}, error: {e}")
                return False
        
        # Check if the rule has the required fields
        required_fields = ["id", "title", "description", "level", "tags", "detection", "logsource"]
        if not all(RuleMethod.get_field(rule, field) for field in required_fields):
            if logger_enabled:
                logger.error(f"Rule {rule_path.name} is missing required fields.")
            return False
        # if logsource['category'] is not in the categories_mapping values
        if RuleMethod.get_field(rule, 'logsource', 'category') not in RuleMethod._categories_mapping.values():
            if logger_enabled:
                logger.warning(f"Rule {rule_path.name} has an invalid category.")
            return False
        # if logsource['product'] is not windows
        if RuleMethod.get_field(rule, 'logsource', 'product') != 'windows':
            if logger_enabled:
                logger.error(f"Rule {rule_path.name} is not a Windows rule.")
            return False
        return True
    

    @staticmethod
    def load_rule_full(rule_path: Path) -> RuleType:
        # Load the rule from the specified path
        if RuleMethod.is_valid_rule(rule_path):
            with open(rule_path, 'r', encoding='utf-8') as f:
                rule = yaml.safe_load(f)
            return rule
        else:
            print(f"Rule {rule_path.name} is not valid.")
            return None
    

    @staticmethod
    def load_rule_filter(rule_path: Path) -> Dict[str, RuleType]:
        # Load the rule from the specified path
        if RuleMethod.is_valid_rule(rule_path):
            with open(rule_path, 'r', encoding='utf-8') as f:
                rule = yaml.safe_load(f)
            rule_value = {field: rule[field] for field in ['detection', 'logsource']}
            rule_value = RuleMethod.prepare_rule(rule_value)
            rule = {rule["id"]: rule_value}
            return rule
        else:
            return None
    

    @staticmethod
    def prepare_rule(rule: RuleType) -> RuleType:
        rule['detection']['evaluation'] = RuleMethod.create_eval_expr(rule)
        # Remove the condition key from the detection block
        rule['detection'].pop('condition', None)
        return rule
    

    @staticmethod
    def create_eval_expr(rule: RuleType) -> str:
        """
        Build an expression that can be evaluated against an event.
        The expression will be used by the filter engine.
        E.g.: selection and not 1 of filter_* -> func(selection) and not any_of(func(filter_1), func(filter_2))
        """
        condition = rule['detection']['condition']
        block_names = [key for key in rule['detection'].keys() if key != 'condition']
        eval_expr = ""

        condition = condition.replace('(', ' ( ')
        condition = condition.replace(')', ' ) ')

        for token in re.split(r'\s+', condition):
            if not token:
                continue
            elif token in ('and', 'or', 'not', 'all', 'of', '1', 'of'):
                eval_expr += token + ' '
                continue
            elif token in ('(', ')'):
                eval_expr += token
                continue
            
            if '*' not in token:
                expr_token = f"self.match_block(rule['detection']['{token}'], event)"
            else:
                func_calls = [f"self.match_block(rule['detection']['{block_name}'], event)"
                              for block_name in block_names if block_name.startswith(token.strip('*'))]
                expr_token = f"({', '.join(func_calls)})"

            eval_expr += expr_token + ' '

        eval_expr = eval_expr.replace('all of ', 'all_of')
        eval_expr = eval_expr.replace('1 of ', 'any_of')
        eval_expr = eval_expr.replace('\\', '\\\\')
        eval_expr = 'self.match_logsource(rule["logsource"], event) and ' + eval_expr
        eval_expr = eval_expr.strip()

        # print(eval_expr)
        return eval_expr
    

    @staticmethod
    def get_field(rule: RuleType, *keys) -> Any:
        # Usefull for getting nested fields from a dictionary
        try:
            for key in keys:
                rule = rule[key]
            return rule
        except KeyError:
            return None
        

    @staticmethod
    def set_field(rule: RuleType, value: Any, *keys) -> RuleType:
        # Usefull for setting nested fields in a dictionary
        try:
            for key in keys[:-1]:
                rule = rule[key]
            rule[keys[-1]] = value
            return rule
        except KeyError:
            return None

    @staticmethod
    def get_expected_category(event_id: int) -> str:
        return RuleMethod._categories_mapping.get(event_id, None)


if __name__ == "__main__":
    rule_path = Path(r"D:\AtSchool\windows-log-analyzer\rules\proc_creation_win_certutil_decode.yml")
    rule = RuleMethod.load_rule_filter(rule_path)
    print(rule)
    # print(RuleItem.create_eval_expr(rule))