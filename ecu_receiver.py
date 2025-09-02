# ecu_receiver.py
import os
import time
import configparser

def log_to_gui(message_type, message, color=None):
    """Prints a formatted string for the GUI to capture."""
    if color:
        print(f"{message_type.upper()}:{message}:{color}", flush=True)
    else:
        print(f"{message_type.upper()}:{message}", flush=True)

def run_receiver():
    config = configparser.ConfigParser()
    time.sleep(1) # Stagger start
    
    log_to_gui('status', 'Listening', '#4CAF50')
    log_to_gui('log', "[o] ECU online. Waiting for firmware...")

    while True:
        try:
            config.read('config.ini')
            watch_folder = config.get('Folders', 'ecu_shared_folder')
            ack_folder = config.get('Folders', 'tcu_ack_folder')
            os.makedirs(watch_folder, exist_ok=True)
            os.makedirs(ack_folder, exist_ok=True)

            files = os.listdir(watch_folder)
            if files:
                filename = files[0]
                filepath = os.path.join(watch_folder, filename)
                
                log_to_gui('status', 'Applying Update', '#ffc107')
                log_to_gui('log', f" New update '{filename}' detected!")
                time.sleep(1)
                log_to_gui('log', " Applying update...")
                time.sleep(2) # Simulate work
                
                log_to_gui('log', " Update applied successfully.")
                os.remove(filepath)
                time.sleep(1)
                log_to_gui('log', f" Cleaned up '{filename}'.")
                
                with open(os.path.join(ack_folder, f"{filename}.ack"), 'w') as f:
                    f.write("SUCCESS")
                log_to_gui('log', "   Sent acknowledgment to TCU.")
                
                log_to_gui('status', 'Success', '#4CAF50')
                time.sleep(3)
                log_to_gui('status', 'Listening', '#4CAF50')
        except Exception as e:
            log_to_gui('log', f"ECU CRITICAL ERROR: {e}")
            log_to_gui('status', 'Crashed', '#f44336')
            time.sleep(5)
        
        time.sleep(1)

if __name__ == '__main__':
    log_to_gui('log', "ECU Receiver process started.")
    run_receiver()