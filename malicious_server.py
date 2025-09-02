# malicious_server.py
import os
import re
import logging
import time
from flask import Flask, jsonify, send_from_directory
from shared_utils import version_to_tuple

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

updates_dir = "malicious_updates"
app = Flask(__name__)

def log_to_gui(message_type, message, color=None):
    """Prints a formatted string for the GUI to capture."""
    if color:
        print(f"{message_type.upper()}:{message}:{color}", flush=True)
    else:
        print(f"{message_type.upper()}:{message}", flush=True)

@app.route('/check-update')
def check_update():
    try:
        log_to_gui('log', f"  TCU connected. Scanning '{updates_dir}'...")
        time.sleep(0.75) # Added delay
        os.makedirs(updates_dir, exist_ok=True)
        files_found = os.listdir(updates_dir)
        
        latest_file = None
        latest_version_tuple = (-1, -1) 
        for filename in files_found:
            match = re.search(r'v([\d.]+)', filename)
            if match:
                version_tuple = version_to_tuple(match.group(1))
                if version_tuple > latest_version_tuple:
                    latest_version_tuple = version_tuple
                    latest_file = filename
        
        if latest_file:
            version_str = ".".join(map(str, latest_version_tuple))
            checksum = "fake_checksum_1234567890abcdef" # A fake checksum
            log_to_gui('log', f"   Serving malicious update: {latest_file} (v{version_str})")
            return jsonify({"version": version_str, "filename": latest_file, "checksum": checksum, "source": "malicious"})
        else:
            return jsonify({"version": "0.0", "source": "malicious"})
    except Exception as e:
        log_to_gui('log', f"[X] MALICIOUS SERVER ERROR: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/download/<string:filename>')
def download_file(filename):
    log_to_gui('log', f" Serving malicious file {filename} to TCU...")
    return send_from_directory(updates_dir, filename)

if __name__ == '__main__':
    try:
        log_to_gui('status', 'Running', '#f44336')
        log_to_gui('log', "[!] Malicious Server process started on port 5001.")
        os.makedirs(updates_dir, exist_ok=True)
        app.run(host='127.0.0.1', port=5001)
    except Exception as e:
        log_to_gui('log', f"[X] MALICIOUS SERVER FATAL CRASH: {e}")
        log_to_gui('status', 'Crashed', '#f44336')




