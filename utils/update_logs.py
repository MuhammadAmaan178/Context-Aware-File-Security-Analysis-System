import re
import os

log_path = 'logs/forensic.log'
ip_suffix = " | Src IP: 192.168.1.100"

if os.path.exists(log_path):
    print(f"Reading {log_path}...")
    with open(log_path, 'r') as f:
        lines = f.readlines()
    
    new_lines = []
    for line in lines:
        line = line.strip()
        if not line: continue
        
        # Check if IP is already there
        if "Src IP:" in line:
            new_lines.append(line)
        else:
            # Append the IP suffix
            new_lines.append(line + ip_suffix)

    with open(log_path, 'w') as f:
        f.write("\n".join(new_lines) + "\n")
    print("Logs updated successfully with IP addresses.")
else:
    print("Log file not found.")
