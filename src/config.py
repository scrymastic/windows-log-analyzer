
from dotenv import load_dotenv
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

load_dotenv()

ROOT = os.getenv('ROOT')
