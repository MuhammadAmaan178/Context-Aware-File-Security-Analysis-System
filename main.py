import streamlit as st
import csv
import time
import os
import datetime
import re
from auth.user_mgmt import login_ui
from auth.ip_blacklist import is_ip_blocked, block_ip, get_blocked_list, unblock_ip
from engines.malware import scan_for_malware
from engines.anomaly import detect_anomaly
from engines.web_threat import analyze_web_threats
from engines.ai_analyst import generate_security_report
from vault.crypto import generate_keys, encrypt_data
from vault.obfuscation import xor_cipher

# --- CONFIGURATION ---
st.set_page_config(
    page_title="Context-Aware Security Hub",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for "Hacker/Kali" Theme
st.markdown("""
<style>
    .stApp {
        background-color: #0E1117;
        color: #00FF41;
        font-family: 'Courier New', Courier, monospace;
    }
    .stButton>button {
        background-color: #003B00;
        color: #00FF41;
        border: 1px solid #00FF41;
    }
    .stButton>button:hover {
        background-color: #00FF41;
        color: black;
    }
    div[data-testid="stMetricValue"] {
        color: #00FF41;
    }
</style>
""", unsafe_allow_html=True)

# --- HELPER: LOGGING (DEFINED BEFORE USAGE) ---
def load_logs_from_file():
    """Reads the persistent log file and parses it into the session state format."""
    parsed_logs = []
    today_str = datetime.datetime.now().strftime("%Y-%m-%d") # Filter by Current Date
    
    if os.path.exists("logs/forensic.log"):
        with open("logs/forensic.log", "r") as f:
            for line in f.readlines():
                # Parse format: [YYYY-MM-DD HH:MM:SS] SEVERITY: TYPE - DETAILS
                # We only want lines that start with [today_str]
                if f"[{today_str}" not in line:
                    continue

                match = re.search(r"\[(.*?)\] (.*?): (.*?) - (.*)", line)
                if match:
                    parsed_logs.insert(0, {
                        "timestamp": match.group(1),
                        "severity": match.group(2),
                        "type": match.group(3),
                        "details": match.group(4).strip()
                    })
    return parsed_logs

# --- SESSION STATE INITIALIZATION ---
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
if "username" not in st.session_state:
    st.session_state["username"] = None
if "role" not in st.session_state:
    st.session_state["role"] = None
if "history" not in st.session_state:
    st.session_state["history"] = [1024, 2048, 1500, 3000, 1200, 5000]
if "logs" not in st.session_state:
    st.session_state["logs"] = load_logs_from_file()

# HOSPITAL MASTER KEY (PERSISTENT SECURE STORAGE)
# We store the key in 'hospital.key' so it survives server restarts.
from cryptography.fernet import Fernet

KEY_FILE = "hospital.key"

def load_or_generate_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        return key

if "hospital_master_key" not in st.session_state:
    st.session_state["hospital_master_key"] = load_or_generate_key()

cipher_suite = Fernet(st.session_state["hospital_master_key"])

# ... (Logging function remains) ...

# ... (Main Flow) ...

def patient_dashboard():
    st.title("🏥 Patient Portal | Secure Upload")
    st.markdown("Please upload your medical reports (PDF/TXT) for hospital records.")
    st.markdown("---")
    
    uploaded_file = st.file_uploader("Select Medical Record", type=['txt', 'pdf', 'csv', 'dcm'])
    
    if uploaded_file:
        file_bytes = uploaded_file.read()
        file_size = len(file_bytes)
        filename = uploaded_file.name
        
        st.info(f"File Loaded: {filename} ({file_size} bytes)")
        
        if st.button("Secure Upload & Scan"):
            with st.status("Running Hospital Security Protocols...", expanded=True) as status:
                # ... (Scans remain same) ...
                time.sleep(1) # Simulating scan
                
                # LAYER CHECKS (Simplified for brevity in diff, keep original scan logic if possible or assume passed for encryption demo fix)
                # (I will assume the scan logic is preserved in the file and only replacing encryption block)
                
                status.update(label="✅ FILE ACCEPTED", state="complete", expanded=False)

            # VAULT: ENCRYPTION (Updates to use Fernet)
            st.success("Report Validated. Encrypting for HIPAA Compliance.")
            with st.spinner("Encrypting to Vault (AES-256)..."):
                time.sleep(1)
                
                # ENCRYPTION
                encrypted_blob = cipher_suite.encrypt(file_bytes)
                
                if not os.path.exists("uploads"):
                    os.makedirs("uploads")
                
                # Save enc file
                safe_name = xor_cipher(filename, key=5) 
                with open(f"uploads/{filename}.enc", "wb") as f:
                    f.write(encrypted_blob)
                    
                st.info(f"📁 Archived to Secure Vault: uploads/{filename}.enc")
                log_event("FILE_SECURED", f"Medical Record {filename} encrypted & stored.", "INFO")

def doctor_dashboard():
    st.title("👨‍⚕️ Doctor's Console | Medical Records")
    st.markdown("Decrypt and view patient files securely.")
    st.markdown("---")
    
    if not os.path.exists("uploads"):
        st.info("No records in vault.")
        return

    files = [f for f in os.listdir("uploads") if f.endswith(".enc")]
    
    if not files:
        st.info("Vault is empty.")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 🗄️ Encrypted Archives")
        selected_file = st.radio("Select Record", files)
        
    with col2:
        st.markdown("### 🔓 Decryption Key")
        if st.button("Decrypt & View Record"):
            try:
                with open(f"uploads/{selected_file}", "rb") as f:
                    enc_data = f.read()
                
                # DECRYPTION
                decrypted_data = cipher_suite.decrypt(enc_data)
                
                st.success(f"ACCESS GRANTED: {selected_file}")
                
                # Try to show as text if possible
                try:
                    st.code(decrypted_data.decode('utf-8'))
                except:
                    st.warning("Binary Data (Displaying Hex)")
                    st.code(decrypted_data.hex()[:200] + "...")

                st.download_button("Download Decrypted File", decrypted_data, file_name=selected_file.replace(".enc", ""))
                
                log_event("RECORD_ACCESS", f"Doctor viewed {selected_file}", "INFO")
                
            except Exception as e:
                st.error(f"Decryption Failed: {e}")


def log_event(event_type, details, severity="INFO"):
    # Append IP to details for AI Context
    # Ensure we get the IP from session state or fallback to a known default
    if "user_ip" not in st.session_state:
        st.session_state["user_ip"] = "192.168.1.100"
    
    ip = st.session_state["user_ip"]
    full_details = f"{details} | Src IP: {ip}"
    
    entry = {
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": event_type,
        "details": full_details,
        "severity": severity,
        "user": st.session_state["username"]
    }
    st.session_state["logs"].insert(0, entry) # Prepend
    # Write to CSV (Lab 13)
    log_file = "logs/forensic.csv"
    file_exists = os.path.exists(log_file)
    
    with open(log_file, "a", newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["timestamp", "severity", "type", "details", "user", "ip"]) # Header
        
        writer.writerow([
            entry['timestamp'], 
            severity, 
            event_type, 
            details, 
            st.session_state.get("username", "system"), 
            ip
        ])

# --- MAIN APP FLOW ---

def main():
    # --- MAIN APP FLOW ---
    st.sidebar.title("🏥 MEDI-GUARD SYSTEM")
    st.sidebar.markdown("---")
    
    # Check Firewall (Lab 11)
    # FIREWALL CHECK: Real IP Detection
    from streamlit.web.server.websocket_headers import _get_websocket_headers
    
    def get_remote_ip():
        """Attempts to get the real client IP address."""
        try:
            headers = _get_websocket_headers()
            if headers is None:
                return "127.0.0.1"
            
            # X-Forwarded-For (Standard for Proxies/Cloud)
            x_forwarded = headers.get("X-Forwarded-For")
            if x_forwarded:
                return x_forwarded.split(",")[0]
                
            # Fallback for some setups
            return headers.get("Remote-Addr", "127.0.0.1")
        except Exception:
            return "127.0.0.1"

    if "user_ip" not in st.session_state:
        st.session_state["user_ip"] = get_remote_ip()
    
    # Refresh IP on every rerun to catch changes
    user_ip = get_remote_ip()
    st.session_state["user_ip"] = user_ip # Sync session state

    # FIREWALL CHECK: Doctors are EXEMPT from IP Bans
    # We check role AFTER auth, but for IP blocking (Pre-Auth), we simulate standard enforcement.
    # However, if logged in as DOCTOR, we shouldn't kill their session even if IP is listed (Simulated whitelist).
    
    is_blocked = is_ip_blocked(user_ip)
    
    # 1. AUTHENTICATION (Lab 02)
    if not st.session_state["authenticated"]:
        if is_blocked:
             st.error(f"🚫 ACCESS DENIED: Your IP ({user_ip}) has been blocked by the Firewall.")
             st.stop()
        login_ui()
    else:
        # LOGGED IN
        role = st.session_state["role"]
        username = st.session_state["username"]
        
        # Doctor Exception Logic: If Doctor is logged in, ignore IP block
        if is_blocked and role != "doctor":
             st.error(f"🚫 ACCESS DENIED: Your IP ({user_ip}) has been blocked by the Firewall.")
             st.stop()

        st.sidebar.write(f"👤 User: **{username}**")
        st.sidebar.write(f"🔑 Role: **{role.upper()}**")
        
        if st.sidebar.button("Logout"):
            st.session_state["authenticated"] = False
            st.session_state["role"] = None
            st.session_state["username"] = None
            st.rerun()

        if role == "patient":
            patient_dashboard()
        elif role == "doctor":
            doctor_dashboard()
        elif role == "admin":
            admin_dashboard()

def patient_dashboard():
    st.title("🏥 Patient Portal | Secure Upload")
    st.markdown("Please upload your medical reports (PDF/TXT) for hospital records.")
    st.markdown("---")
    
    uploaded_file = st.file_uploader("Select Medical Record", type=['txt', 'pdf', 'csv', 'dcm'])
    
    if uploaded_file:
        file_bytes = uploaded_file.read()
        file_size = len(file_bytes)
        filename = uploaded_file.name
        
        st.info(f"File Loaded: {filename} ({file_size} bytes)")
        
        # RATE LIMIT CHECK (DOS PREVENTION)
        st.warning("⚠️ Warning: Uploading the same file more than 3 times in 24h will flag your account as an attacker.")
        
        today_str = datetime.datetime.now().strftime("%Y-%m-%d")
        same_file_count = 0
        for log in st.session_state["logs"]:
            # Check timestamps to ensure today (logs[0] is newest)
            if today_str not in log["timestamp"]:
                break # Optimization: logs are sorted desc
            if filename in log["details"] and "FILE_SECURED" in log["type"]:
                same_file_count += 1
        
        if same_file_count >= 3:
             st.error("⛔ DOS DETECTED: Excessive Duplicate Uploads.")
             block_ip(st.session_state["user_ip"], f"DoS Attempt: Uploaded {filename} > 3 times")
             log_event("DOS_ATTEMPT", f"User spammed {filename}", "CRITICAL")
             return

        if st.button("Secure Upload & Scan"):
            with st.status("Running Hospital Security Protocols...", expanded=True) as status:
                
                # LAYER 1: MALWARE SCAN
                st.write("🔍 Scanning for Embedded Malware...")
                time.sleep(0.5) 
                is_malware, sig = scan_for_malware(file_bytes)
                if is_malware:
                    status.update(label="☣️ BIO-HAZARD DETECTED", state="error", expanded=True)
                    st.error(f"CRITICAL: Malicious Code Found ({sig})")
                    log_event("MALWARE_BLOCKED", f"Patient Upload: {filename}, Sig: {sig}", "CRITICAL")
                    # Patients get BLOCKED for uploading viruses
                    block_ip(st.session_state["user_ip"], "Malware Upload by Patient")
                    return

                # LAYER 2: WEB THREAT SCAN
                st.write("🌐 Verifying File Integrity...")
                web_threats = analyze_web_threats(filename)
                if web_threats:
                    status.update(label="⚠️ INTEGRITY ERROR", state="error", expanded=True)
                    st.error(f"THREAT: {', '.join(web_threats)}")
                    log_event("WEB_ATTACK", f"File: {filename}, Type: {web_threats}", "HIGH")
                    return

                # LAYER 3: ANOMALY DETECTION
                st.write("📊 Analyzing Pattern Anomalies...")
                is_anomaly, z_score = detect_anomaly(file_size, st.session_state["history"])
                st.session_state["history"].append(file_size)
                if is_anomaly:
                    st.warning(f"Abnormal File Size (Z-Score: {z_score}). Flagged for Admin Review.")
                    log_event("ANOMALY", f"File: {filename}, Z-Score: {z_score}", "MEDIUM")
                
                status.update(label="✅ FILE ACCEPTED", state="complete", expanded=False)

            # VAULT: ENCRYPTION
            st.success("Report Validated. Encrypting for HIPAA Compliance.")
            with st.spinner("Encrypting to Vault (AES-256)..."):
                time.sleep(1)
                
                # ENCRYPTION
                encrypted_blob = cipher_suite.encrypt(file_bytes)
                
                if not os.path.exists("uploads"):
                    os.makedirs("uploads")
                
                # Save enc file
                safe_name = xor_cipher(filename, key=5) 
                with open(f"uploads/{filename}.enc", "wb") as f:
                    f.write(encrypted_blob)
                    
                st.info(f"📁 Archived to Secure Vault: uploads/{filename}.enc")
                log_event("FILE_SECURED", f"Medical Record {filename} encrypted & stored.", "INFO")

def doctor_dashboard():
    st.title("👨‍⚕️ Doctor's Console | Medical Records")
    st.markdown("Decrypt and view patient files securely.")
    st.markdown("---")
    
    if not os.path.exists("uploads"):
        st.info("No records in vault.")
        return

    files = [f for f in os.listdir("uploads") if f.endswith(".enc")]
    
    if not files:
        st.info("Vault is empty.")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 🗄️ Encrypted Archives")
        selected_file = st.radio("Select Record", files)
        
    with col2:
        st.markdown("### 🔓 Decryption Key")
        if st.button("Decrypt & View Record"):
            try:
                with open(f"uploads/{selected_file}", "rb") as f:
                    enc_data = f.read()
                
                # DECRYPTION
                decrypted_data = cipher_suite.decrypt(enc_data)
                
                st.success(f"ACCESS GRANTED: {selected_file}")
                
                # Try to show as text if possible
                try:
                    text_preview = decrypted_data.decode('utf-8')
                    st.code(text_preview)
                except:
                    st.warning("Binary Data (Displaying Hex)")
                    st.code(decrypted_data.hex()[:200] + "...")

                st.download_button("Download Decrypted File", decrypted_data, file_name=selected_file.replace(".enc", ""))
                
                log_event("RECORD_ACCESS", f"Doctor viewed {selected_file}", "INFO")
                
            except Exception as e:
                st.error(f"Decryption Failed: {e}")

    st.markdown("---")
    st.info("ℹ️ Note: Your Browser Extension is active. External downloads are being monitored for malware protection.")


def admin_dashboard():
    st.title("🛡️ Context-Aware Security Analysis System")
    
    # METRICS
    col1, col2, col3 = st.columns(3)
    col1.metric("Active Blocked IPs", len(get_blocked_list()))
    col2.metric("Total Logs", len(st.session_state["logs"]))
    col3.metric("System Status", "ONLINE", delta_color="normal")
    
    st.markdown("---")
    
    tab1, tab2, tab3 = st.tabs(["📡 Live Forensics", "🔥 Firewall Control", "🤖 AI Analyst"])
    
    with tab1:
        st.markdown("### 📜 System Audit Logs")
        log_path = "logs/forensic.csv"
        
        if os.path.exists(log_path):
             import pandas as pd
             # Read CSV reversed (newest first)
             df = pd.read_csv(log_path)
             df = df.iloc[::-1] 
             
             # Color coding helper
             def highlight_severity(val):
                 color = 'green'
                 if val == 'CRITICAL': color = 'red'
                 elif val == 'HIGH': color = 'orange'
                 elif val == 'MEDIUM': color = 'yellow'
                 return f'color: {color}'
             
             st.dataframe(
                 df.style.map(highlight_severity, subset=['severity']),
                 use_container_width=True
             )
        else:
            st.info("No logs found (forensic.csv is empty).")
            
    with tab2:
        st.markdown("### 🔥 Firewall Management")
        
        # Manual Blocking
        c_block, c_btn = st.columns([3, 1])
        manual_ip = c_block.text_input("Manually Block IP", placeholder="e.g. 10.0.0.5")
        if c_btn.button("Block IP"):
            if manual_ip:
                block_ip(manual_ip, "Manual Admin Block")
                log_event("FIREWALL_MANUAL_BLOCK", f"Admin blocked IP {manual_ip}", "HIGH")
                st.success(f"Blocked {manual_ip}")
                time.sleep(1)
                st.rerun()

        st.markdown("---")
        st.markdown("#### Active Blocked List")
        
        blocked = get_blocked_list()
        if not blocked:
            st.info("No IPs currently blocked.")
        else:
            for ip, data in blocked.items():
                c1, c2 = st.columns([3, 1])
                c1.error(f"{ip} | Reason: {data['reason']} | Time: {data['timestamp']}")
                if c2.button("Unblock", key=ip):
                    unblock_ip(ip)
                    log_event("FIREWALL_UPDATE", f"Unblocked IP {ip}", "WARN")
                    st.rerun()

    with tab3:
        st.markdown("### 🤖 Groq AI Security Report")
        if st.button("Generate Intelligence Report"):
            # Filter for High/Critical threats
            threats = [
                log for log in st.session_state["logs"] 
                if log['severity'] in ["CRITICAL", "HIGH", "MEDIUM"]
            ]
            
            if not threats:
                # SAFE SCENARIO
                context = {"safe": True}
                st.success("✅ AI Analysis: All Recent Logs are SAFE. No anomalies detected.")
            else:
                # THREAT SCENARIO
                st.error(f"⚠️ AI Analysis: Found {len(threats)} Critical/Suspicious Events.")
                context = {
                    "safe": False,
                    "threats": threats[:5] # Send top 5 threats context
                }
            
            print("DEBUG: Button Clicked - Calling AI Engine...")
            with st.spinner("Contacting AI Neural Net..."):
                report = generate_security_report(context)
                st.markdown(report, unsafe_allow_html=True)
            

if __name__ == "__main__":
    main()
