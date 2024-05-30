
from config import ROOT
import logging
import colorlog


# Create a custom logger
logger = logging.getLogger(__name__)

logger.setLevel(logging.INFO)

c_handler = logging.StreamHandler()
f_handler = logging.FileHandler(ROOT / 'src' / 'utils' / 'logs.log')
c_handler.setLevel(logging.INFO)
f_handler.setLevel(logging.INFO)

c_format = colorlog.ColoredFormatter(
    "%(log_color)s%(module)s - %(levelname)s - %(message)s%(reset)s",
    log_colors={
        'DEBUG':    'cyan',
        'INFO':     'green',
        'WARNING':  'yellow',
        'ERROR':    'red',
        'CRITICAL': 'red,bg_white',
    },
    reset=True,
    style='%'
)

f_format = logging.Formatter('%(asctime)s - %(module)s - %(levelname)s - %(message)s')

c_handler.setFormatter(c_format)
f_handler.setFormatter(f_format)

logger.addHandler(c_handler)
logger.addHandler(f_handler)