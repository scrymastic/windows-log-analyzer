


class RuleEngine:
    def __init__(self):
        pass

    def check_rule(self, rule):
        # Check if the rule is legit
        pass

    def add_rule(self, rule):
        # Add the rule to the legit-rules folder
        pass
    
    def remove_rule(self, rule):
        # Remove the rule from the legit-rules folder
        pass

    def deploy_rule(self, rule):
        # Deploy the rule to the rule engine
        # By moving the rule from the legit-rules folder to the active-rules folder
        # As follows:
        # /active-rules/detections/{rule_id}.yml: log source, detection
        # /active-rules/headers/{rule_id}.yml: title
        # /active-rules/metadata/{rule_id}.yml: add filename field, other metadata
        pass

    def undeploy_rule(self, rule):
        # Undeploy the rule from the rule engine
        # By moving the rule from the active-rules folder to the legit-rules folder
        pass

    def get_active_rules(self):
        # Return the list of active rules
        # Load the rules from the /active-rules/detections folder
        pass

    def search_rules(self, keyword):
        # Return the list of rules that contain the keyword
        pass
