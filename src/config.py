
import os

try:
    from colorama import Fore, Style
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    CYAN = Fore.CYAN
    MAGENTA = Fore.MAGENTA
    RESET = Style.RESET_ALL
except ImportError:
    RED = ""
    GREEN = ""
    YELLOW = ""
    CYAN = ""
    MAGENTA = ""
    RESET = ""

ROOT = "D:\\AtSchool\\windows-log-analyzer"

EVENT_VIEWER_LOGS = os.getenv("SystemRoot") + "\\System32\\winevt\\Logs"
