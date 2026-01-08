import streamlit as st
import hashlib

# Mock Database for Lab 02 AAA
# In a real scenario, this would check 'database.db'
import csv
import os

# CSV Database Path
DB_FILE = os.path.join(os.path.dirname(__file__), "users.csv")

def load_users():
    """Reads users from CSV into a dictionary."""
    users = {}
    if not os.path.exists(DB_FILE):
        return users
        
    with open(DB_FILE, mode='r', newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            users[row['username']] = {
                "password_hash": row['password_hash'],
                "role": row['role']
            }
    return users

def verify_login(username, password):
    """
    Lab 02: AAA Framework (Authentication).
    Verifies username and password hash against CSV database.
    """
    users = load_users()
    
    print(f"DEBUG: Attempting login for '{username}'")
    if username in users:
        # Check hash
        input_hash = hashlib.sha256(password.encode()).hexdigest()
        stored_hash = users[username]["password_hash"]
        
        if input_hash == stored_hash:
            return users[username]["role"]
            
    return None

def login_ui():
    """
    Renders a 'Hacker Style' Login Screen in Streamlit.
    """
    st.markdown("## 🔐 Medi-Guard Access Portal")
    
    col1, col2 = st.columns(2)
    with col1:
        username = st.text_input("Username", placeholder="e.g., dr_smith").strip()
    with col2:
        password = st.text_input("Password", type="password", placeholder="••••••").strip()
    
    st.info("💡 **Demo Credentials:**")
    st.markdown("- **Admin:** `admin` / `admin123`")
    st.markdown("- **Doctor:** `dr_smith` / `doctor123`")
    st.markdown("- **Patient:** `patient_01` / `patient123`")
        
    if st.button("Authenticate"):
        # Explicit strip again just in case
        username = username.strip()
        password = password.strip()
        
        role = verify_login(username, password)
        if role:
            st.session_state["authenticated"] = True
            st.session_state["username"] = username
            st.session_state["role"] = role
            st.success(f"Access Granted. Identity: {role.upper()}")
            st.rerun()
        else:
            st.error("Access Denied: Invalid Credentials")
