# oem_server.py
import os
import re
import logging
import time
from flask import Flask, jsonify, send_from_directory
from shared_utils import calculate_sha256, version_to_tuple

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

updates_dir = "updates"
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
        log_to_gui('log', f" TCU connected. Scanning '{updates_dir}'...")
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
            filepath = os.path.join(updates_dir, latest_file)
            checksum = calculate_sha256(filepath)
            log_to_gui('log', f"   Latest version available: {latest_file} (v{version_str})")
            return jsonify({"version": version_str, "filename": latest_file, "checksum": checksum, "source": "oem"})
        else:
            log_to_gui('log', "   No valid update files found.")
            return jsonify({"version": "0.0", "source": "oem"})
    except Exception as e:
        log_to_gui('log', f"  OEM SERVER ERROR: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/download/<string:filename>')
def download_file(filename):
    log_to_gui('log', f" Serving {filename} to TCU...")
    return send_from_directory(updates_dir, filename)

if __name__ == '__main__':
    try:
        log_to_gui('status', 'Running', '#4CAF50')
        log_to_gui('log', "[+] OEM Server process started on port 5000.")
        os.makedirs(updates_dir, exist_ok=True)
        app.run(host='127.0.0.1', port=5000)
    except Exception as e:
        log_to_gui('log', f"[X] OEM SERVER FATAL CRASH: {e}")
        log_to_gui('status', 'Crashed', '#f44336')




