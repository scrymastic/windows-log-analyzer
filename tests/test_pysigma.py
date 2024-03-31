from sigma import SigmaLoader, SigmaScanner
import test_log_parser

# SteS 2: Load Sigma Rules
sigma_loader = SigmaLoader()
sigma_rules = sigma_loader.load_rules('/path/to/sigma/rules')

# Step 3: Search for Matches
sigma_scanner = SigmaScanner(sigma_rules)
log_data = [
    # Log data goes here
    # Each entry represents a log event
    # For example: {"timestamp": "2022-01-01T12:00:00", "message": "Some log message"}
]
matches = sigma_scanner.scan(log_data)
# Step 4: Process Matches
for match in matches:
    print("Match found:")
    print(match)
