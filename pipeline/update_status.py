import json
import os
import sys

# pipeline/update_status.py
# Usage: python3 update_status.py sast completed sca running

STATUS_FILE = "dashboard/data/status.json"

def update_status(updates):
    # Load existing or create new
    if os.path.exists(STATUS_FILE):
        with open(STATUS_FILE, "r") as f:
            try:
                status = json.load(f)
            except:
                status = {"is_scanning": True}
    else:
        status = {"is_scanning": True}

    # Apply updates from command line arguments
    # Args format: key1 value1 key2 value2 ...
    for i in range(0, len(updates), 2):
        if i + 1 < len(updates):
            key = updates[i]
            val = updates[i+1]
            status[key] = val
            print(f"[*] Status Update: {key} -> {val}")

    # Write back
    os.makedirs(os.path.dirname(STATUS_FILE), exist_ok=True)
    with open(STATUS_FILE, "w") as f:
        json.dump(status, f)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        update_status(sys.argv[1:])
    else:
        print("Usage: python3 update_status.py <key> <value> ...")
