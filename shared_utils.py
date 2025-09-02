# shared_utils.py
import hashlib
import re
import os

def find_latest_version(folders_to_scan):
    """
    Scans a list of folders to find the highest version number from filenames.
    e.g., "firmware_v1.2.bin" -> (1, 2)
    """
    latest_version_tuple = (0, 0)
    for folder in folders_to_scan:
        if not os.path.exists(folder):
            continue
        for filename in os.listdir(folder):
            match = re.search(r'v([\d.]+)', filename)
            if match:
                version_tuple = version_to_tuple(match.group(1))
                if version_tuple > latest_version_tuple:
                    latest_version_tuple = version_tuple
    return latest_version_tuple

def calculate_sha256(filepath):
    """Calculates the SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (IOError, FileNotFoundError):
        return None

def version_to_tuple(v_str):
    """
    Converts a version string 'x.y.z' to a tuple of ints (major, minor)
    for robust comparison.
    """
    try:
        if v_str is None: return (0, 0)
        parts = str(v_str).strip().split('.')
        
        major = int(parts[0]) if len(parts) > 0 and parts[0].isdigit() else 0
        minor = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        
        return (major, minor)
    except (ValueError, TypeError):
        return (0, 0)