import shutil
import os

# Define the source path and destination path
source_path = r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx"
destination_folder = r"data_access"

# Create the destination folder if it doesn't exist
os.makedirs(destination_folder, exist_ok=True)

# Define the destination path
destination_path = os.path.join(destination_folder, "Sysmon.evtx")

# Copy the file
shutil.copy2(source_path, destination_path)