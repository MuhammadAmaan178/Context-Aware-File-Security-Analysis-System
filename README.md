# 🏥 MediGuard: Context-Aware Security Analysis System

**MediGuard** is a comprehensive, military-grade security dashboard designed for hospital environments. It implements a **Zero-Trust Architecture** to protect sensitive medical records from Malware, Web Threats, and Insider Attacks.

![MediGuard Shield](chrome_extension/icon128.png)

## 🌟 Key Features

### 🛡️ Core Engines
1.  **Malware Detection Engine**: Signature-based scanning for known threats (e.g., EICAR).
2.  **Web Threat Engine**: Detects SQL Injection & XSS patterns in filenames (e.g., `report_UNION_SELECT.txt`).
3.  **Anomaly Detection Engine**: Uses Statistical Z-Score analysis to flag suspicious file sizes.
4.  **AI Analyst (Groq/Llama 3)**: Generates human-readable, intelligence-grade security reports.

### 🔒 Zero-Trust Vault
*   **AES-256 Encryption**: All safe files are encrypted using `cryptography` (Fernet) before storage.
*   **Role-Based Access Control (RBAC)**:
    *   **Admin**: View Logs, Manage Firewall, AI Analysis.
    *   **Doctor**: Decrypt & View Patient Records.
    *   **Patient**: Upload Records (subject to strict scanning).

### 🌐 Chrome Extension (Endpoint Protection)
*   **Real-Time Interception**: Pauses every download in the browser.
*   **Remote Scanning**: Sends file to the MediGuard Core for analysis.
*   **Action**: Unblocks safe files / Cancels dangerous ones automatically.

---

## 🚀 Installation & Setup

### Prerequisites
*   Python 3.8+
*   Google Chrome

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configuration
Create a `.env` file in the root directory:
```env
GROQ_API_KEY=your_groq_api_key_here
```

---

## 🖥️ Usage Guide

### Terminal 1: Launch The Dashboard
```bash
python -m streamlit run main.py
```
*   **Access**: `http://localhost:8501`
*   **Login Credentials**:
    *   **Admin**: `admin` / `admin123`
    *   **Doctor**: `dr_smith` / `doctor123`
    *   **Patient**: `patient_01` / `patient123`

### Terminal 2: Start Extension Bridge
```bash
python utils/api_bridge.py
```
*   **Status**: Listens on `http://localhost:5000`

### Browser: Load Extension
1.  Open `chrome://extensions/`
2.  Enable **Developer Mode**.
3.  Click **Load Unpacked** -> Select `chrome_extension` folder.

---

## 📂 Project Structure
*   `main.py`: Central Dashboard & Logic.
*   `engines/`: Security analysis modules (Malware, Anomaly, Web, AI).
*   `auth/`: User authentication & IP Firewall.
*   `vault/`: Encryption & Obfuscation logic.
*   `chrome_extension/`: Browser-side code (`manifest.json`, `background.js`).
*   `utils/api_bridge.py`: Flask server connecting Chrome to Python.

---

## ⚠️ Educational Purpose
This project is for **Information Security Lab** demonstration purposes.

---
*Developed by Muhammad Amaan*
