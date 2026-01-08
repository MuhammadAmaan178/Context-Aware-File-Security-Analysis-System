import re
from urllib.parse import unquote

def analyze_web_threats(filename: str):
    """
    Lab 10: Web Threat Analysis (SQLi & XSS in filenames/URLs).
    Returns: list[str] -> List of detected threats
    """
    threats = []
    
    # Decode URL-encoded characters (e.g., %3C -> <)
    decoded_str = unquote(filename)
    
    # SQL Injection Patterns
    # SQL Injection Patterns
    # Updated to handle underscores/hyphens common in filenames (e.g. UNION_SELECT)
    sqli_patterns = [
        r"DROP[\s_-]+TABLE", 
        r"UNION[\s_-]+SELECT", 
        r"OR[\s_-]+1=1", 
        r"SELECT[\s_-]+\*"
    ]
    for pattern in sqli_patterns:
        # Check both original and decoded
        if re.search(pattern, filename, re.IGNORECASE) or re.search(pattern, decoded_str, re.IGNORECASE):
            threats.append("SQL Injection Attempt")

    # XSS Patterns
    xss_patterns = [r"<script>", r"javascript:", r"onload=", r"onerror="]
    for pattern in xss_patterns:
        # Check both original and decoded
        if re.search(pattern, filename, re.IGNORECASE) or re.search(pattern, decoded_str, re.IGNORECASE):
            threats.append("Cross-Site Scripting (XSS)")

    return list(set(threats)) # Remove duplicates
