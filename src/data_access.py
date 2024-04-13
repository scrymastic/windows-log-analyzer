

import os
from pathlib import Path
from config import *


# load data from local log file
class DataAccess():
    def __init__(self):
        self.system_root = os.getenv('SystemRoot')
        self.event_viewer_logs = Path(self.system_root, "System32", "winevt", "Logs")
        self.sample_logs = Path(ROOT, "sample-logs")


    def search_log_files(self, log_folder: Path, keyword: str) -> list:
        if isinstance(log_folder, str):
            log_folder = Path(log_folder)
        # Search for evtx log files in the specified folder
        matching_log_files = []
        log_files = list(log_folder.glob("**/*.evtx"))
        for log_file in log_files:
            if keyword.lower() in log_file.name.lower():
                matching_log_files.append(log_file)
        return matching_log_files
    

