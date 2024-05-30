

from src.config import ROOT, EVENT_VIEWER_LOGS
from pathlib import Path
from typing import List


# load data from local log file
class DataAccess:

    def __init__(self):
        self._event_viewer_logs = Path(EVENT_VIEWER_LOGS)
        self._sample_logs = ROOT / "sample-logs"


    def search_log_files(self, log_folder: Path, keywords: List[str]) -> List[Path]:
        if isinstance(log_folder, str):
            log_folder = Path(log_folder)
        # Search for evtx log files in the specified folder
        matching_log_files = []
        log_files = list(log_folder.rglob("*.evtx"))
        for log_file in log_files:
            if all(keyword.lower() in str(log_file).lower() for keyword in keywords):
                matching_log_files.append(log_file)
        return matching_log_files
    

if __name__ == "__main__":
    pass

