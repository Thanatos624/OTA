# gui_app.py
import tkinter as tk
from tkinter import scrolledtext, Frame, Label, Button, ttk
import threading
import queue
import os
import shutil
import configparser
import subprocess
import sys
from shared_utils import find_latest_version

class OTASimulatorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("OTA Update Simulator: OEM vs. Malicious Server")
        self.root.geometry("1600x900")
        self.root.configure(bg="#2E2E2E")

        self.log_queue = queue.Queue()
        self.simulation_running = False
        self.processes = []

        control_frame = Frame(self.root, bg="#2E2E2E")
        control_frame.pack(pady=10, fill="x")
        
        self.start_stop_button = Button(control_frame, text="Start Simulation", command=self.toggle_simulation, bg="#4CAF50", fg="white", font=("Helvetica", 12, "bold"), relief="flat", padx=10)
        self.start_stop_button.pack(side="left", padx=20)
        
        self.deploy_oem_button = Button(control_frame, text="Deploy OEM Update", command=self.deploy_oem_update, bg="#2196F3", fg="white", font=("Helvetica", 10, "bold"))
        self.deploy_oem_button.pack(side="left", padx=10)

        self.deploy_malicious_button = Button(control_frame, text="Deploy Malicious Update", command=self.deploy_malicious_update, bg="#E57373", fg="white", font=("Helvetica", 10, "bold"))
        self.deploy_malicious_button.pack(side="left", padx=10)
        
        self.toggle_checksum_button = Button(control_frame, text="Checksum Verification: ON", command=self.toggle_checksum_verification, bg="#4CAF50", fg="white", font=("Helvetica", 10))
        self.toggle_checksum_button.pack(side="left", padx=20)
        
        self.clear_button = Button(control_frame, text="Clear All Logs", command=self.clear_logs, bg="#607d8b", fg="white", font=("Helvetica", 10))
        self.clear_button.pack(side="right", padx=20)

        top_frame = Frame(self.root, bg="#2E2E2E")
        top_frame.pack(fill="both", expand=True)
        bottom_frame = Frame(self.root, bg="#2E2E2E")
        bottom_frame.pack(fill="both", expand=True)

        self.server_frame, self.server_status = self.create_log_frame(top_frame, "OEM Server")
        self.malicious_server_frame, self.malicious_server_status = self.create_log_frame(top_frame, "Malicious Server")
        self.tcu_frame, self.tcu_status = self.create_log_frame(bottom_frame, "TCU Client (Vulnerable)")
        self.ecu_frame, self.ecu_status = self.create_log_frame(bottom_frame, "ECU Receiver")
        
        self.server_log = self.create_log_box(self.server_frame)
        self.malicious_server_log = self.create_log_box(self.malicious_server_frame)
        self.tcu_log = self.create_log_box(self.tcu_frame)
        self.ecu_log = self.create_log_box(self.ecu_frame)
        
        self.progress_bar = ttk.Progressbar(self.tcu_frame, orient="horizontal", length=100, mode="determinate")
        self.progress_bar.pack(fill="x", padx=5, pady=5)

        self.root.after(100, self.process_queue)
        self.ensure_config_exists()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

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
                box_map = {'server': self.server_log, 'malicious_server': self.malicious_server_log, 'tcu': self.tcu_log, 'ecu': self.ecu_log}
                status_map = {'server': self.server_status, 'malicious_server': self.malicious_server_status, 'tcu': self.tcu_status, 'ecu': self.ecu_status}
                
                if msg_type == 'log':
                    box = box_map.get(target)
                    if box:
                        box.configure(state='normal'); box.insert(tk.END, message + '\n'); box.configure(state='disabled'); box.see(tk.END)
                elif msg_type == 'status':
                    indicator = status_map.get(target)
                    if indicator: indicator.config(text=message, bg=color)
                elif msg_type == 'progress' and target == 'tcu':
                    self.progress_bar['value'] = float(message)
        except queue.Empty: pass
        finally: self.root.after(100, self.process_queue)

    def parse_and_log(self, line, target_component):
        line = line.strip()
        if not line: return
        
        parts = line.split(':', 1)
        if len(parts) != 2:
            self.log_queue.put(('log', target_component, line, None))
            return

        msg_type, content = parts[0].lower().strip(), parts[1].strip()
        
        if msg_type == 'status':
            status_parts = content.split(':', 1)
            color = status_parts[1].strip() if len(status_parts) == 2 else "#FFFFFF"
            self.log_queue.put(('status', target_component, status_parts[0].strip(), color))
        elif msg_type in ['log', 'progress']:
            self.log_queue.put((msg_type, target_component, content, None))
        else:
            self.log_queue.put(('log', target_component, line, None))

    def stream_reader(self, process_stdout, target_component):
        try:
            for line in iter(process_stdout.readline, ''):
                self.parse_and_log(line, target_component)
        finally:
            process_stdout.close()
            
    def ensure_config_exists(self):
        config = configparser.ConfigParser()
        config.read('config.ini')
        if not config.has_section('TCU'): config.add_section('TCU')
        if not config.has_option('TCU', 'current_version'): config.set('TCU', 'current_version', '1.0')
        if not config.has_option('TCU', 'poll_interval_seconds'): config.set('TCU', 'poll_interval_seconds', '10')
        
        if not config.has_section('Server'): config.add_section('Server')
        if not config.has_option('Server', 'oem_url'): config.set('Server', 'oem_url', 'http://127.0.0.1:5000')
        if not config.has_option('Server', 'malicious_url'): config.set('Server', 'malicious_url', 'http://127.0.0.1:5001')

        if not config.has_section('Security'): config.add_section('Security')
        if not config.has_option('Security', 'checksum_verification_enabled'): config.set('Security', 'checksum_verification_enabled', 'true')
        
        if not config.has_section('Folders'): config.add_section('Folders')
        if not config.has_option('Folders', 'ecu_shared_folder'): config.set('Folders', 'ecu_shared_folder', 'shared_for_ecu')
        if not config.has_option('Folders', 'tcu_download_folder'): config.set('Folders', 'tcu_download_folder', 'tcu_downloads')
        if not config.has_option('Folders', 'tcu_ack_folder'): config.set('Folders', 'tcu_ack_folder', 'tcu_acks')
        
        with open('config.ini', 'w') as configfile: config.write(configfile)
        self.checksum_enabled = config.getboolean('Security', 'checksum_verification_enabled')

    def toggle_simulation(self):
        if self.simulation_running: self.stop_simulation()
        else: self.start_simulation()

    def start_simulation(self):
        self.simulation_running = True
        self.clear_logs()
        
        folders = ['updates', 'malicious_updates', 'shared_for_ecu', 'tcu_acks', 'tcu_downloads']
        for folder in folders:
            if os.path.exists(folder): shutil.rmtree(folder)
            os.makedirs(folder)

        with open("updates/firmware_v1.0.bin", "w") as f: f.write("Baseline firmware v1.0.")

        self.ensure_config_exists() # Resets config to defaults
        
        self.start_stop_button.config(text="Stop Simulation", bg="#f44336")

        scripts = {'server': 'oem_server.py', 'malicious_server': 'malicious_server.py', 'tcu': 'tcu_client.py', 'ecu': 'ecu_receiver.py'}
        for name, script_file in scripts.items():
            try:
                process = subprocess.Popen([sys.executable, script_file],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                    text=True, encoding='utf-8', errors='replace', bufsize=1,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
                self.processes.append(process)
                thread = threading.Thread(target=self.stream_reader, args=(process.stdout, name), daemon=True)
                thread.start()
            except FileNotFoundError:
                self.log_queue.put(('log', name, f"ERROR: Could not find '{script_file}'.", None))
                self.stop_simulation()
                return

    def stop_simulation(self):
        self.simulation_running = False
        for p in self.processes:
            if p.poll() is None: p.terminate()
        self.processes.clear()
        
        self.start_stop_button.config(text="Start Simulation", bg="#4CAF50")
        for status in [self.server_status, self.malicious_server_status, self.tcu_status, self.ecu_status]:
            status.config(text="Stopped", bg="gray")
        
    def deploy_oem_update(self): self.deploy_update("oem")
    def deploy_malicious_update(self): self.deploy_update("malicious")

    def deploy_update(self, source):
        if not self.simulation_running:
            self.log_queue.put(('log', 'server' if source == 'oem' else 'malicious_server', "Cannot deploy update. Simulation is not running.", None))
            return

        latest_version_tuple = find_latest_version(['updates', 'malicious_updates'])
        major, minor = latest_version_tuple
        new_version_str = f"{major}.{minor + 1}"
        
        target_folder, filename_prefix, content_prefix, log_target, log_msg_prefix = (
            ("updates", "firmware_v", "Legitimate firmware content", "server", "OEM DEPLOY") if source == "oem" else
            ("malicious_updates", "malicious_firmware_v", "!!! MALICIOUS PAYLOAD", "malicious_server", "MALICIOUS DEPLOY")
        )
        
        filename = f"{filename_prefix}{new_version_str}.bin"
        content = f"{content_prefix} for version {new_version_str}"
        with open(os.path.join(target_folder, filename), "w") as f: f.write(content)
        self.log_queue.put(('log', log_target, f" {log_msg_prefix}: Deployed '{filename}'.", None))

    def toggle_checksum_verification(self):
        self.checksum_enabled = not self.checksum_enabled
        config = configparser.ConfigParser()
        config.read('config.ini')
        config.set('Security', 'checksum_verification_enabled', str(self.checksum_enabled))
        with open('config.ini', 'w') as configfile: config.write(configfile)
        
        if self.checksum_enabled:
            self.toggle_checksum_button.config(text="Checksum Verification: ON", bg="#4CAF50")
            if self.simulation_running: self.log_queue.put(('log', 'tcu', "SECURITY ENABLED: Checksum verification is ON.", None))
        else:
            self.toggle_checksum_button.config(text="Checksum Verification: OFF", bg="#f44336")
            if self.simulation_running: self.log_queue.put(('log', 'tcu', "SECURITY DISABLED: Checksum verification is OFF.", None))

    def clear_logs(self):
        for log_box in [self.server_log, self.malicious_server_log, self.tcu_log, self.ecu_log]:
            log_box.configure(state='normal'); log_box.delete('1.0', tk.END); log_box.configure(state='disabled')
    
    def on_closing(self):
        if self.simulation_running: self.stop_simulation()
        self.root.destroy()

if __name__ == '__main__':
    root = tk.Tk()
    app = OTASimulatorApp(root)
    root.mainloop()