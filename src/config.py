
from pathlib import Path
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
    RED, GREEN, YELLOW, CYAN, MAGENTA, RESET = "", "", "", "", "", ""
    print("Colorama not found, colored output will not be available.")


ROOT = Path(__file__).resolve().parent.parent

# Default path to event viewer logs
EVENT_VIEWER_LOGS = Path(os.getenv("SystemRoot")) / "System32" / "winevt" / "Logs"

# Vietnam local timezone
LOCAL_TIMEZONE = 7