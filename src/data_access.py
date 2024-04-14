

from pathlib import Path
from config import *


# load data from local log file
class DataAccess():
    def __init__(self):
        self.event_viewer_logs = Path(EVENT_VIEWER_LOGS)
        self.sample_logs = Path(ROOT, "sample-logs")


    def search_log_files(self, log_folder: Path, keywords: list) -> list:
        if isinstance(log_folder, str):
            log_folder = Path(log_folder)
        # Search for evtx log files in the specified folder
        matching_log_files = []
        log_files = list(log_folder.glob("**/*.evtx"))
        for log_file in log_files:
            if all(keyword.lower() in str(log_file).lower() for keyword in keywords):
                matching_log_files.append(log_file)
        return matching_log_files
    

