from flask import Flask, request, jsonify
from flask_cors import CORS
import sys
import os

# Add parent directory to path to import engines
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engines.web_threat import analyze_web_threats
from engines.malware import scan_for_malware
from vault.obfuscation import xor_cipher
from cryptography.fernet import Fernet
import datetime

import csv

def log_event_bridge(event_type, details, severity="INFO"):
    """
    Writes to the shared forensic.csv file.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_file = "logs/forensic.csv"
    file_exists = os.path.exists(log_file)
    
    try:
        if not os.path.exists("logs"):
            os.makedirs("logs")
            
        with open(log_file, "a", newline='') as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(["timestamp", "severity", "type", "details", "user", "ip"])
            
            writer.writerow([timestamp, severity, event_type, details, "extension_agent", "N/A"])
            
        print(f"LOGGED: {event_type}")
    except Exception as e:
        print(f"Logging Failed: {e}")

app = Flask(__name__)
CORS(app) # Enable Cross-Origin requests from Chrome Extension

@app.route('/api/status', methods=['GET'])
def status():
    return jsonify({"status": "online", "system": "Context-Aware Security System"})

@app.route('/api/scan', methods=['POST'])
def scan_file():
    """
    Endpoint for Chrome Extension to send file URLs, filenames, OR content content.
    """
    try:
        data = request.json
        url = data.get('url', '')
        filename = data.get('filename', '') # Support download filename
        content_str = data.get('content', '') # Actual file content (Deep Scan)
        
        print(f"DEBUG: Received Scan Request for: {filename} from {url}")
        if content_str:
            print(f"DEBUG: Content Length: {len(content_str)} chars")
        else:
            print("DEBUG: No Content Payload (URL check only)")
        
        all_threats = []
        verdict = "SAFE"
        risk_score = 0

        # 1. Web Treat Analysis (URL/Filename)
        threats_url = analyze_web_threats(url)
        threats_file = analyze_web_threats(filename) if filename else []
        all_threats.extend(threats_url + threats_file)
        
        # 2. Malware Scan (Content)
        if content_str:
            # Convert string back to bytes for signature matching
            # In a real app, we'd handle binary blobs differently (e.g. base64)
            # For this lab, assume text-based malware or robust encoding
            content_bytes = content_str.encode('utf-8', errors='ignore')
            is_malware, sig = scan_for_malware(content_bytes)
            
            if is_malware:
                all_threats.append(f"Malware Signature: {sig}")
                verdict = "MALWARE"
                risk_score = 100

        all_threats = list(set(all_threats))
        
        if all_threats:
            if verdict == "SAFE": verdict = "DANGEROUS" # Downgrade only if not MALWARE
            risk_score = 100
            
            # Log to Forensic Log
            log_event_bridge("MALWARE_BLOCKED_EXT", f"Extension Blocked {filename} | Type: {all_threats}", "CRITICAL")

            return jsonify({
                "url": url,
                "filename": filename,
                "verdict": verdict,
                "threats": all_threats,
                "risk_score": risk_score
            })
        
        # --- SAFE PATH: ENCRYPT & VAULT ---
        try:
            # 1. Load Hospital Key
            if os.path.exists("hospital.key"):
                with open("hospital.key", "rb") as f:
                    key = f.read()
                cipher = Fernet(key)
                
                # 2. Encrypt Content
                # content_str is text/unicode. We need bytes.
                original_bytes = content_str.encode('utf-8', errors='ignore')
                encrypted_blob = cipher.encrypt(original_bytes)
                
                # 3. Save to Uploads
                if not os.path.exists("uploads"):
                    os.makedirs("uploads")
                
                # Obfuscate Name
                safe_name = xor_cipher(filename, key=5)
                
                # UNIQUE FILENAME LOGIC
                base_name = filename
                counter = 1
                while os.path.exists(f"uploads/{base_name}.enc"):
                    name, ext = os.path.splitext(filename)
                    base_name = f"{name}_{counter}{ext}"
                    counter += 1
                
                save_path = f"uploads/{base_name}.enc" 
                
                with open(save_path, "wb") as f:
                    f.write(encrypted_blob)
                    
                print(f"DEBUG: Saved Encrypted Artifact to {save_path}")
                log_event_bridge("FILE_SECURED_EXT", f"Doctor Download {base_name} encrypted & stored.", "INFO")
                
            else:
                print("ERROR: hospital.key not found! Cannot encrypt.")
                log_event_bridge("SYSTEM_ERROR", "Missing hospital.key during extension download", "HIGH")
                
        except Exception as e:
            print(f"Encryption Failed: {e}")
            log_event_bridge("ENCRYPTION_FAIL", f"Failed to vault {filename}: {str(e)}", "HIGH")

        return jsonify({
            "url": url,
            "filename": filename,
            "verdict": "SAFE",
            "vault_name": f"{safe_name}.enc" if 'safe_name' in locals() else "Not Saved",
            "threats": [],
            "risk_score": 0
        })
    except Exception as e:
        print(f"Scan Error: {e}")
        return jsonify({"verdict": "ERROR", "error": str(e)}), 500

if __name__ == '__main__':
    print("Starting Context-Aware API Bridge on port 8000...")
    app.run(port=8000)
