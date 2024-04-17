
import os


try:
    from colorama import Fore, Style, init
    init(autoreset=True)
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

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")

# Default path to event viewer logs
EVENT_VIEWER_LOGS = os.path.join(os.getenv("SystemRoot"), "System32", "winevt", "Logs")

# Vietnam local timezone
TIMEZONE = 7