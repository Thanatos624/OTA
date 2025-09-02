# tcu_client.py
import requests
import time
import os
import shutil
import configparser
from shared_utils import version_to_tuple, calculate_sha256

def log_to_gui(message_type, message, color=None):
    """Prints a formatted string for the GUI to capture."""
    if color:
        print(f"{message_type.upper()}:{message}:{color}", flush=True)
    else:
        print(f"{message_type.upper()}:{message}", flush=True)

def check_single_server(server_url):
    """Checks one server for an update."""
    if not server_url: return None
    try:
        response = requests.get(f"{server_url}/check-update", timeout=3)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException:
        return None

def download_and_process(config, firmware_info, checksum_verification_enabled):
    log_to_gui('status', 'Downloading', '#ffc107')
    log_to_gui('progress', '0')
    time.sleep(0.75)

    source = firmware_info.get("source", "unknown")
    server_url = config.get('Server', f'{source}_url')
    
    try:
        filename = firmware_info['filename']
        download_url = f"{server_url}/download/{filename}"
        dl_response = requests.get(download_url, stream=True, timeout=10)
        dl_response.raise_for_status()
        
        total_size = int(dl_response.headers.get('content-length', 0))
        temp_dir = config['Folders']['tcu_download_folder']
        os.makedirs(temp_dir, exist_ok=True)
        temp_filepath = os.path.join(temp_dir, filename)
        
        bytes_downloaded = 0
        with open(temp_filepath, 'wb') as f:
            for chunk in dl_response.iter_content(chunk_size=8192):
                f.write(chunk)
                bytes_downloaded += len(chunk)
                if total_size > 0:
                    log_to_gui('progress', f"{(bytes_downloaded / total_size) * 100}")
        
        log_to_gui('log', " Download complete.")
        log_to_gui('progress', '100')
        time.sleep(0.75)

        log_to_gui('status', 'Verifying', '#9c27b0')
        log_to_gui('log', " Verifying file integrity...")
        time.sleep(0.75)
        local_checksum = calculate_sha256(temp_filepath)
        log_to_gui('log', f"   Server checksum: {firmware_info['checksum']}")
        log_to_gui('log', f"   Local checksum:  {local_checksum}")
        time.sleep(0.75)

        if checksum_verification_enabled and local_checksum != firmware_info['checksum']:
            log_to_gui('log', " CHECKSUM MISMATCH! Deleting corrupt file.")
            os.remove(temp_filepath)
            return False
        
        if not checksum_verification_enabled:
            log_to_gui('log', "    WARNING: Checksum verification is disabled!")
        
        log_to_gui('log', " Checksum match! File is valid.")
        time.sleep(0.75)
        ecu_folder = config['Folders']['ecu_shared_folder']
        os.makedirs(ecu_folder, exist_ok=True)
        shutil.move(temp_filepath, os.path.join(ecu_folder, filename))
        log_to_gui('log', f" Transferred '{filename}' from {source.upper()} server to ECU folder.")
        
        return wait_for_ecu_ack(config, filename)

    except Exception as e:
        log_to_gui('log', f" Download/Processing Error: {e}")
        return False

def wait_for_ecu_ack(config, filename):
    log_to_gui('status', 'Awaiting ACK', '#673ab7')
    log_to_gui('log', f"   Waiting for acknowledgment from ECU for {filename}...")
    ack_folder = config['Folders']['tcu_ack_folder']
    os.makedirs(ack_folder, exist_ok=True)
    ack_path = os.path.join(ack_folder, f"{filename}.ack")
    
    for _ in range(30): # Wait for 30 seconds
        if os.path.exists(ack_path):
            log_to_gui('log', f" ACK received from ECU for {filename}.")
            os.remove(ack_path) 
            return True
        time.sleep(1)
        
    log_to_gui('log', " Timed out waiting for ECU acknowledgment.")
    return False

def run_client():
    config = configparser.ConfigParser()
    time.sleep(2)

    while True:
        try:
            config.read('config.ini')
            poll_interval = config.getint('TCU', 'poll_interval_seconds', fallback=10)
            current_version_str = config.get('TCU', 'current_version', fallback='1.0')
            oem_url = config.get('Server', 'oem_url')
            malicious_url = config.get('Server', 'malicious_url')
            checksum_enabled = config.getboolean('Security', 'checksum_verification_enabled', fallback=True)
            current_version_tuple = version_to_tuple(current_version_str)

            log_to_gui('status', 'Checking', '#2196F3')
            log_to_gui('log', f" TCU (v{current_version_str}) checking all sources for updates...")
            time.sleep(1) # Delay
            
            oem_info = check_single_server(oem_url)
            malicious_info = check_single_server(malicious_url)

            best_update = None
            best_version_tuple = current_version_tuple

            if oem_info and version_to_tuple(oem_info.get("version")) > best_version_tuple:
                best_update = oem_info
                best_version_tuple = version_to_tuple(oem_info.get("version"))
            
            if malicious_info and version_to_tuple(malicious_info.get("version")) > best_version_tuple:
                best_update = malicious_info
                best_version_tuple = version_to_tuple(malicious_info.get("version"))

            if best_update:
                source = best_update.get('source', 'unknown').upper()
                log_to_gui('log', f" New update found from {source} server! Version: {best_update['version']}")
                time.sleep(0.75)
                
                if download_and_process(config, best_update, checksum_enabled):
                    config.set('TCU', 'current_version', best_update['version'])
                    with open('config.ini', 'w') as configfile: config.write(configfile)
                    log_to_gui('log', f"   Version updated to {best_update['version']} in config.ini")
                    log_to_gui('status', 'Success', '#4CAF50')
                else:
                    log_to_gui('status', 'Failed', '#f44336')
            else:
                log_to_gui('log', " No new updates found.")
                log_to_gui('status', 'Idle', 'gray')
        
        except Exception as e:
            log_to_gui('log', f"TCU CRITICAL ERROR: {e}")
            log_to_gui('status', 'Crashed', '#f44336')
        
        time.sleep(poll_interval)

if __name__ == '__main__':
    log_to_gui('log', "TCU Client process started.")
    run_client()