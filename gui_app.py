import tkinter as tk
from tkinter import scrolledtext, Frame, Label, Button, ttk, filedialog, simpledialog
import threading
import time
import queue
import os
import shutil
import configparser
import re
from flask import Flask, jsonify, send_from_directory, request
import logging
import requests

# --- Universal Helper Functions ---
def calculate_sha256(filepath):
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (IOError, FileNotFoundError):
        return None
import hashlib

def version_to_tuple(v_str):
    """Converts a version string 'x.y.z' to a tuple of ints (x, y, z) for robust comparison."""
    try:
        if v_str is None: return (0, 0)
        parts = str(v_str).split('.')
        # Ensure at least two components for major/minor comparison
        while len(parts) < 2:
            parts.append('0')
        return tuple(map(int, parts))
    except (ValueError, TypeError):
        return (0, 0)

# --- GUI Application Class ---
class OTASimulatorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("OTA Update Visual Simulator (Advanced)")
        self.root.geometry("1400x800")
        self.root.configure(bg="#2E2E2E")

        self.log_queue = queue.Queue()
        
        # --- State flags for simulations ---
        self.simulation_running = False
        self.simulate_network_error = False
        self.simulate_corrupt_file = False
        self.tcu_target_is_oem = True
        self.checksum_verification_enabled = True

        # --- Control Frame ---
        control_frame = Frame(self.root, bg="#2E2E2E")
        control_frame.pack(pady=10, fill="x")
        
        self.start_stop_button = Button(control_frame, text="Start Simulation", command=self.toggle_simulation, bg="#4CAF50", fg="white", font=("Helvetica", 12, "bold"), relief="flat", padx=10)
        self.start_stop_button.pack(side="left", padx=20)
        
        self.toggle_checksum_button = Button(control_frame, text="Checksum Verification: ON", command=self.toggle_checksum_verification, bg="#4CAF50", fg="white", font=("Helvetica", 10))
        self.toggle_checksum_button.pack(side="left", padx=10)
        
        self.error_button = Button(control_frame, text="Simulate Network Error", command=self.toggle_network_error, bg="#f44336", fg="white", font=("Helvetica", 10))
        self.error_button.pack(side="left", padx=10)
        
        self.corrupt_button = Button(control_frame, text="Simulate Corrupt File", command=self.toggle_corrupt_file, bg="#ff9800", fg="white", font=("Helvetica", 10))
        self.corrupt_button.pack(side="left", padx=10)
        
        self.clear_button = Button(control_frame, text="Clear All Logs", command=self.clear_logs, bg="#607d8b", fg="white", font=("Helvetica", 10))
        self.clear_button.pack(side="right", padx=20)

        # --- Log Panels Container (2x2 Grid) ---
        top_frame = Frame(self.root, bg="#2E2E2E")
        top_frame.pack(fill="both", expand=True)
        bottom_frame = Frame(self.root, bg="#2E2E2E")
        bottom_frame.pack(fill="both", expand=True)

        self.server_frame, self.server_status = self.create_log_frame(top_frame, "OEM Server")
        self.malicious_server_frame, self.malicious_server_status = self.create_log_frame(top_frame, "Malicious Server")
        self.tcu_frame, self.tcu_status = self.create_log_frame(bottom_frame, "TCU Client")
        self.ecu_frame, self.ecu_status = self.create_log_frame(bottom_frame, "ECU Receiver")
        
        # --- Add Server-Specific Buttons ---
        self.deploy_oem_minor_button = Button(self.server_frame, text="Deploy Minor Update", command=lambda: self.deploy_auto_update(False, 'minor'), bg="#00bcd4", fg="white", font=("Helvetica", 9))
        self.deploy_oem_minor_button.pack(side='left', padx=10, pady=5)
        self.deploy_oem_major_button = Button(self.server_frame, text="Deploy Major Update", command=lambda: self.deploy_auto_update(False, 'major'), bg="#009688", fg="white", font=("Helvetica", 9))
        self.deploy_oem_major_button.pack(side='left', padx=10, pady=5)
        
        self.deploy_malicious_minor_button = Button(self.malicious_server_frame, text="Deploy Minor Update", command=lambda: self.deploy_auto_update(True, 'minor'), bg="#e91e63", fg="white", font=("Helvetica", 9))
        self.deploy_malicious_minor_button.pack(side='left', padx=10, pady=5)
        self.deploy_malicious_major_button = Button(self.malicious_server_frame, text="Deploy Major Update", command=lambda: self.deploy_auto_update(True, 'major'), bg="#c2185b", fg="white", font=("Helvetica", 9))
        self.deploy_malicious_major_button.pack(side='left', padx=10, pady=5)

        # --- Add TCU Server Switch Button ---
        self.switch_server_button = Button(self.tcu_frame, text="Switch to Malicious Server", command=self.switch_tcu_target, bg="#4CAF50", fg="white", font=("Helvetica", 9))
        self.switch_server_button.pack(pady=5)

        self.server_log = self.create_log_box(self.server_frame)
        self.malicious_server_log = self.create_log_box(self.malicious_server_frame)
        self.tcu_log = self.create_log_box(self.tcu_frame)
        self.ecu_log = self.create_log_box(self.ecu_frame)
        
        self.progress_bar = ttk.Progressbar(self.tcu_frame, orient="horizontal", length=100, mode="determinate")
        self.progress_bar.pack(fill="x", padx=5, pady=5)

        self.root.after(100, self.process_queue)
        self.ensure_config_exists()

    def create_log_frame(self, parent, title):
        frame = Frame(parent, bg="#3C3C3C", bd=2, relief="sunken")
        frame.pack(side="left", fill="both", expand=True, padx=10, pady=5)
        title_frame = Frame(frame, bg="#3C3C3C")
        title_frame.pack(fill="x", padx=5, pady=5)
        label = Label(title_frame, text=title, font=("Helvetica", 16, "bold"), bg="#3C3C3C", fg="#FFFFFF")
        label.pack(side="left")
        status_indicator = Label(title_frame, text="Stopped", font=("Helvetica", 10, "italic"), bg="gray", fg="white", padx=5, pady=2)
        status_indicator.pack(side="right")
        return frame, status_indicator

    def create_log_box(self, parent_frame):
        log_box = scrolledtext.ScrolledText(parent_frame, state='disabled', wrap=tk.WORD, bg="#1E1E1E", fg="#E0E0E0", font=("Consolas", 10))
        log_box.pack(expand=True, fill="both", padx=5, pady=5)
        return log_box

    def process_queue(self):
        try:
            while True:
                msg_type, target, message, color = self.log_queue.get_nowait()
                box_map = {'server': self.server_log, 'malicious': self.malicious_server_log, 'tcu': self.tcu_log, 'ecu': self.ecu_log}
                status_map = {'server': self.server_status, 'malicious': self.malicious_server_status, 'tcu': self.tcu_status, 'ecu': self.ecu_status}
                if msg_type == 'log':
                    box = box_map[target]
                    box.configure(state='normal')
                    box.insert(tk.END, message + '\n')
                    box.configure(state='disabled')
                    box.see(tk.END)
                elif msg_type == 'status':
                    indicator = status_map[target]
                    indicator.config(text=message, bg=color)
                elif msg_type == 'progress':
                    self.progress_bar['value'] = message
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.process_queue)
            
    def ensure_config_exists(self):
        config = configparser.ConfigParser()
        config.read('config.ini')
        
        if not config.has_section('TCU'): config.add_section('TCU')
        if not config.has_option('TCU', 'current_version'): config.set('TCU', 'current_version', '1.0')
        if not config.has_option('TCU', 'poll_interval_seconds'): config.set('TCU', 'poll_interval_seconds', '15')
            
        if not config.has_section('Server'): config.add_section('Server')
        if not config.has_option('Server', 'oem_url'): config.set('Server', 'oem_url', 'http://127.0.0.1:5000')
        if not config.has_option('Server', 'malicious_url'): config.set('Server', 'malicious_url', 'http://127.0.0.1:5001')

        if not config.has_section('Folders'): config.add_section('Folders')
        if not config.has_option('Folders', 'ecu_shared_folder'): config.set('Folders', 'ecu_shared_folder', 'shared_for_ecu')
        if not config.has_option('Folders', 'tcu_download_folder'): config.set('Folders', 'tcu_download_folder', 'tcu_downloads')
        if not config.has_option('Folders', 'tcu_ack_folder'): config.set('Folders', 'tcu_ack_folder', 'tcu_acks')

        with open('config.ini', 'w') as configfile:
            config.write(configfile)

    def toggle_simulation(self):
        if self.simulation_running:
            self.simulation_running = False
            self.log_message('server', 'log', "🛑 Shutdown signal received...")
            self.log_message('malicious', 'log', "🛑 Shutdown signal received...")
            self.log_message('tcu', 'log', "🛑 Stopping TCU client...")
            self.log_message('ecu', 'log', "🛑 Stopping ECU receiver...")
            try:
                requests.get("http://127.0.0.1:5000/shutdown")
                requests.get("http://127.0.0.1:5001/shutdown")
            except requests.exceptions.ConnectionError: pass
            self.start_stop_button.config(text="Start Simulation", bg="#4CAF50")
            for status in [self.server_status, self.malicious_server_status, self.tcu_status, self.ecu_status]:
                status.config(text="Stopped", bg="gray")
        else:
            self.simulation_running = True
            
            for folder in ['updates', 'updates_malicious', 'shared_for_ecu', 'tcu_acks', 'tcu_downloads']:
                if os.path.exists(folder):
                    shutil.rmtree(folder)
                os.makedirs(folder)

            config = configparser.ConfigParser()
            config.read('config.ini')
            config.set('TCU', 'current_version', '1.0')
            with open('config.ini', 'w') as configfile: config.write(configfile)
            self.clear_logs()
            self.start_stop_button.config(text="Stop Simulation", bg="#f44336")
            threading.Thread(target=self.run_oem_server, daemon=True).start()
            threading.Thread(target=self.run_malicious_server, daemon=True).start()
            threading.Thread(target=self.run_tcu_client, daemon=True).start()
            threading.Thread(target=self.run_ecu_receiver, daemon=True).start()

    def deploy_auto_update(self, is_malicious, update_type):
        target_folder = "updates_malicious" if is_malicious else "updates"
        target_log = "malicious" if is_malicious else "server"
        
        latest_version_tuple = (0, 0)
        if os.path.exists(target_folder) and os.listdir(target_folder):
            for filename in os.listdir(target_folder):
                match = re.search(r'v([\d.]+)', filename)
                if match:
                    version_tuple = version_to_tuple(match.group(1))
                    if version_tuple > latest_version_tuple:
                        latest_version_tuple = version_tuple
        
        major, minor = latest_version_tuple[0], latest_version_tuple[1]
        
        if update_type == 'minor':
            new_version_str = f"{major}.{minor + 1}"
        else: # major
            new_version_str = f"{major + 1}.0"

        new_filename = f"firmware_v{new_version_str}.bin"
        dest_path = os.path.join(target_folder, new_filename)
        
        with open(dest_path, "w") as f:
            f.write(f"Firmware content for version {new_version_str}")
        
        self.log_message(target_log, 'log', f"✅ Auto-deployed '{new_filename}'.")

    def switch_tcu_target(self):
        if self.tcu_target_is_oem:
            self.tcu_target_is_oem = False
            self.switch_server_button.config(text="Switch to OEM Server", bg="#f44336")
            self.log_message('tcu', 'log', "ATTACK: TCU is now targeting the MALICIOUS server.")
        else:
            self.tcu_target_is_oem = True
            self.switch_server_button.config(text="Switch to Malicious Server", bg="#4CAF50")
            self.log_message('tcu', 'log', "DEFENSE: TCU is now targeting the OEM server.")

    def toggle_checksum_verification(self):
        if self.checksum_verification_enabled:
            self.checksum_verification_enabled = False
            self.toggle_checksum_button.config(text="Checksum Verification: OFF", bg="#f44336")
            self.log_message('tcu', 'log', "SECURITY DISABLED: Checksum verification is OFF.")
        else:
            self.checksum_verification_enabled = True
            self.toggle_checksum_button.config(text="Checksum Verification: ON", bg="#4CAF50")
            self.log_message('tcu', 'log', "SECURITY ENABLED: Checksum verification is ON.")

    def toggle_network_error(self): self.simulate_network_error = True; self.log_message('tcu', 'log', "🕹️ Network Error armed.", None)
    def toggle_corrupt_file(self): self.simulate_corrupt_file = True; self.log_message('tcu', 'log', "🕹️ File Corruption armed.", None)
    def clear_logs(self):
        for log_box in [self.server_log, self.malicious_server_log, self.tcu_log, self.ecu_log]:
            log_box.configure(state='normal'); log_box.delete('1.0', tk.END); log_box.configure(state='disabled')

    def log_message(self, target, msg_type, message, color='white'): self.log_queue.put((msg_type, target, message, color))

    def create_server_app(self, is_malicious):
        log = logging.getLogger(f'werkzeug_{"malicious" if is_malicious else "oem"}')
        log.setLevel(logging.ERROR)
        app = Flask(__name__)
        server_log_target = "malicious" if is_malicious else "server"
        updates_dir = "updates_malicious" if is_malicious else "updates"

        def shutdown_server():
            func = request.environ.get('werkzeug.server.shutdown')
            if func: func()
        
        @app.route('/shutdown')
        def shutdown(): shutdown_server(); return 'Server shutting down...'

        @app.route('/check-update')
        def check_update():
            self.log_message(server_log_target, 'log', f"✅ TCU connected. Scanning '{updates_dir}'...")
            os.makedirs(updates_dir, exist_ok=True)
            
            files_found = os.listdir(updates_dir)
            self.log_message(server_log_target, 'log', f"   Files found: {files_found or 'None'}")

            latest_file, latest_version_tuple = None, (0, 0)
            for filename in files_found:
                match = re.search(r'v([\d.]+)', filename)
                if match:
                    version_tuple = version_to_tuple(match.group(1))
                    if version_tuple > latest_version_tuple:
                        latest_version_tuple, latest_file = version_tuple, filename
            
            if latest_file:
                version_str = '.'.join(map(str, latest_version_tuple))
                checksum = calculate_sha256(os.path.join(updates_dir, latest_file))
                if is_malicious:
                    checksum = "FAKE_CHECKSUM_FROM_ATTACKER_12345"
                self.log_message(server_log_target, 'log', f"   Determined latest: {latest_file} (v{version_str})")
                return jsonify({"version": version_str, "filename": latest_file, "checksum": checksum})
            else:
                self.log_message(server_log_target, 'log', "   No valid update files found.")
                return jsonify({"version": "0.0"})

        @app.route('/download/<string:filename>')
        def download_file(filename):
            self.log_message(server_log_target, 'log', f"⬇️ Serving {filename} to TCU...")
            return send_from_directory(updates_dir, filename)
            
        @app.route('/report-status', methods=['POST'])
        def report_status():
            data = request.json
            self.log_message(server_log_target, 'log', f"ACK Received for '{data['filename']}' with status: {data['status']}")
            return jsonify({"message": "Acknowledged"})
        
        return app

    def run_oem_server(self):
        self.log_message('server', 'status', 'Running', '#4CAF50')
        self.log_message('server', 'log', "🚀 OEM Server started.")
        if not os.path.exists("updates") or not os.listdir("updates"):
            os.makedirs("updates", exist_ok=True)
            with open("updates/firmware_v1.0.bin", "w") as f: f.write("Default firmware.")
        self.create_server_app(False).run(host='127.0.0.1', port=5000)

    def run_malicious_server(self):
        self.log_message('malicious', 'status', 'Running', '#e91e63')
        self.log_message('malicious', 'log', "🚀 Malicious Server started.")
        self.create_server_app(True).run(host='127.0.0.1', port=5001)

    def run_tcu_client(self):
        time.sleep(2)
        config = configparser.ConfigParser()
        config.read('config.ini')
        poll_interval = config.getint('TCU', 'poll_interval_seconds')

        while self.simulation_running:
            config.read('config.ini')
            current_version_str = config['TCU']['current_version']
            current_version_tuple = version_to_tuple(current_version_str)
            server_url = config['Server']['oem_url'] if self.tcu_target_is_oem else config['Server']['malicious_url']
            
            version_str_for_log = '.'.join(map(str, current_version_tuple))
            self.log_message('tcu', 'status', 'Checking', '#2196F3')
            self.log_message('tcu', 'log', f"🚙 TCU (v{version_str_for_log}) checking for updates at {server_url}...")
            try:
                response = requests.get(f"{server_url}/check-update", timeout=5)
                response.raise_for_status()
                latest_info = response.json()
                self.log_message('tcu', 'log', f"   Server response: v{latest_info.get('version')}")
                latest_version_tuple = version_to_tuple(latest_info.get("version"))
                
                if latest_version_tuple > current_version_tuple:
                    self.log_message('tcu', 'log', f"✨ New update found! Version: {latest_info['version']}")
                    success = self.download_and_process(config, latest_info, server_url)
                    if success:
                        config.set('TCU', 'current_version', latest_info['version'])
                        with open('config.ini', 'w') as configfile: config.write(configfile)
                        self.log_message('tcu', 'log', f"   Version updated to {latest_info['version']} in config.ini")
                        self.log_message('tcu', 'status', 'Success', '#4CAF50')
                    else:
                        self.log_message('tcu', 'status', 'Failed', '#f44336')
                else:
                    self.log_message('tcu', 'log', "👍 No new updates found.")
                    self.log_message('tcu', 'status', 'Idle', 'gray')
            except requests.exceptions.RequestException as e:
                if self.simulation_running:
                    self.log_message('tcu', 'log', f"❌ Could not connect to server: {e}")
                    self.log_message('tcu', 'status', 'Failed', '#f44336')
            
            for _ in range(poll_interval):
                if not self.simulation_running: break
                time.sleep(1)

    def download_and_process(self, config, firmware_info, server_url):
        self.log_message('tcu', 'status', 'Downloading', '#ffc107')
        self.log_message('progress', 'progress', 0, None)
        
        if self.simulate_network_error:
            time.sleep(1); self.simulate_network_error = False
            self.log_message('tcu', 'log', "❌ SIMULATED NETWORK ERROR."); return False

        try:
            filename = firmware_info['filename']
            download_url = f"{server_url}/download/{filename}"
            dl_response = requests.get(download_url, stream=True)
            dl_response.raise_for_status()
            
            total_size, bytes_downloaded = int(dl_response.headers.get('content-length', 0)), 0
            temp_dir = config['Folders']['tcu_download_folder']
            os.makedirs(temp_dir, exist_ok=True)
            temp_filepath = os.path.join(temp_dir, filename)
            
            with open(temp_filepath, 'wb') as f:
                for chunk in dl_response.iter_content(chunk_size=8192):
                    if not self.simulation_running: self.log_message('tcu', 'log', "🛑 Download cancelled."); return False
                    f.write(chunk)
                    bytes_downloaded += len(chunk)
                    if total_size > 0: self.log_message('progress', 'progress', (bytes_downloaded / total_size) * 100, None)
            
            self.log_message('tcu', 'log', "✅ Download complete.")
            self.log_message('progress', 'progress', 100, None)

            if self.simulate_corrupt_file:
                self.simulate_corrupt_file = False
                self.log_message('tcu', 'log', "🕹️ Simulating file corruption...")
                with open(temp_filepath, 'a') as f: f.write("junk_data")

            self.log_message('tcu', 'status', 'Verifying', '#9c27b0')
            self.log_message('tcu', 'log', "🔐 Verifying file integrity...")
            self.log_message('tcu', 'log', f"   Server checksum: {firmware_info['checksum']}")
            self.log_message('tcu', 'log', f"   Local checksum:  {calculate_sha256(temp_filepath)}")
            
            is_valid = True
            if self.checksum_verification_enabled:
                if calculate_sha256(temp_filepath) != firmware_info['checksum']:
                    is_valid = False
            else:
                self.log_message('tcu', 'log', "   ⚠️ WARNING: Checksum verification is disabled!")

            if is_valid:
                self.log_message('tcu', 'log', "👍 Checksum match! File is valid.")
                ecu_folder = config['Folders']['ecu_shared_folder']
                os.makedirs(ecu_folder, exist_ok=True)
                shutil.move(temp_filepath, os.path.join(ecu_folder, filename))
                self.log_message('tcu', 'log', f"📦 Transferred {filename} to ECU folder.")
                return self.wait_for_ecu_ack(config, filename, server_url)
            else:
                self.log_message('tcu', 'log', "❌ CHECKSUM MISMATCH! Deleting corrupt file.")
                os.remove(temp_filepath)
                return False
        except requests.exceptions.RequestException as e:
            if self.simulation_running: self.log_message('tcu', 'log', f"❌ Download failed: {e}")
            return False

    def wait_for_ecu_ack(self, config, filename, server_url):
        self.log_message('tcu', 'status', 'Awaiting ACK', '#673ab7')
        self.log_message('tcu', 'log', f"   Waiting for acknowledgment from ECU for {filename}...")
        ack_folder = config['Folders']['tcu_ack_folder']
        os.makedirs(ack_folder, exist_ok=True)
        ack_path = os.path.join(ack_folder, f"{filename}.ack")
        
        for _ in range(30):
            if os.path.exists(ack_path):
                self.log_message('tcu', 'log', f"✅ ACK received from ECU for {filename}.")
                os.remove(ack_path) 
                self.report_status_to_server(server_url, filename, "SUCCESS")
                return True
            if not self.simulation_running: return False
            time.sleep(1)
            
        self.log_message('tcu', 'log', f"❌ Timed out waiting for ECU acknowledgment.")
        return False

    def report_status_to_server(self, server_url, filename, status):
        try:
            self.log_message('tcu', 'log', f"   Reporting status '{status}' to server...")
            requests.post(f"{server_url}/report-status", json={"filename": filename, "status": status}, timeout=5)
            self.log_message('tcu', 'log', "   Server acknowledged the status report.")
        except requests.exceptions.RequestException as e:
            self.log_message('tcu', 'log', f"   Could not report status to server: {e}")

    def run_ecu_receiver(self):
        time.sleep(1)
        config = configparser.ConfigParser()
        config.read('config.ini')
        watch_folder = config['Folders']['ecu_shared_folder']
        ack_folder = config['Folders']['tcu_ack_folder']
        os.makedirs(watch_folder, exist_ok=True)
        os.makedirs(ack_folder, exist_ok=True)
        self.log_message('ecu', 'status', 'Listening', '#4CAF50')
        self.log_message('ecu', 'log', f"🧠 ECU online. Listening in '{watch_folder}'...")
        
        while self.simulation_running:
            try:
                files = os.listdir(watch_folder)
                if files:
                    self.log_message('ecu', 'status', 'Applying Update', '#ffc107')
                    filename = files[0]
                    filepath = os.path.join(watch_folder, filename)
                    self.log_message('ecu', 'log', f"💡 New update '{filename}' detected!")
                    self.log_message('ecu', 'log', "⚙️ Applying update...")
                    time.sleep(2)
                    self.log_message('ecu', 'log', "✅ Update applied successfully.")
                    os.remove(filepath)
                    self.log_message('ecu', 'log', f"🗑️ Cleaned up '{filename}'.")
                    
                    with open(os.path.join(ack_folder, f"{filename}.ack"), 'w') as f: f.write("SUCCESS")
                    self.log_message('ecu', 'log', f"   Sent acknowledgment to TCU.")
                    
                    self.log_message('ecu', 'status', 'Success', '#4CAF50')
                    time.sleep(3)
                    self.log_message('ecu', 'status', 'Listening', '#4CAF50')
            except FileNotFoundError: pass
            time.sleep(1)


if __name__ == '__main__':
    root = tk.Tk()
    app = OTASimulatorApp(root)
    root.mainloop()
