import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

def generate_security_report(context: dict):
    """
    Lab 14: AI-Powered Explainable Security.
    Uses Groq (Llama 3) to generate a narrative report.
    """
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return "⚠️ Error: GROQ_API_KEY not found in .env"

    try:
        client = Groq(api_key=api_key)
        
        # Prepare prompt based on context
        if context.get("safe"):
            prompt = """
            You are 'Context-Aware Security AI'.
            SYSTEM STATUS: ALL CLEAR.
            
            Task:
            1. Confirm no critical threats were detected in the recent logs.
            2. Commend the user for maintaining good security hygiene.
            3. Sign off with "Context-Aware Security System | STATUS: GREEN".
            """
        else:
            # Build a clear text status of threats
            threat_lines = []
            for t in context.get("threats", []):
                threat_lines.append(f"--- EVENT ---")
                threat_lines.append(f"TIME: {t['timestamp']}")
                threat_lines.append(f"TYPE: {t['type']}")
                threat_lines.append(f"DETAILS: {t['details']}")
            
            threats_text = "\n".join(threat_lines)

            prompt = f"""
            You are 'Context-Aware Security AI', a military-grade Cyber Defense Agent.
            CRITICAL THREATS DETECTED. Analyze the following audit log snippet:
            
            {threats_text}
            
            INSTRUCTIONS:
            Generate a **Structured Security Report** in Markdown format. Use the following exact structure:
            
            ### 🚨 Threat Intelligence Brief
            | Parameter | Status |
            | :--- | :--- |
            | **Threat Level** | 🔴 CRITICAL |
            | **Detected Malware** | [Name of Virus/Sig or 'None'] |
            | **Attack Vector** | [e.g. File Upload, SQL Injection] |
            | **Source IP** | [EXTRACT IP FROM LOGS] |
            
            #### 📝 Tactical Analysis
            [Write 2-3 sentences explaining the attack technically. Be concise.]
            
            #### 🛡️ Countermeasures
            1. **Block Source IP:** [Repeat IP here] immediately.
            2. **Quarantine:** Isolate the infected endpoint.
            3. [One other relevant action]
            
            ---
            *Status: THREAT DETECTED | Confidence: 99.9%*
            """

        chat_completion = client.chat.completions.create(
            messages=[
                {"role": "system", "content": "You are a tactical cybersecurity AI. Be precise and extracting IPs is your top priority."},
                {"role": "user", "content": prompt}
            ],
            model="llama-3.3-70b-versatile",
        )
        return chat_completion.choices[0].message.content
    except Exception as e:
        return f"AI System Failure: {str(e)}"
