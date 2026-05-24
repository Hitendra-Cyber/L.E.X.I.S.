import random

def ask_cyber_bot(user_query):
    """
    Enhanced local Cyber Threat Intelligence Engine.
    Handles basic conversational edge cases (greetings, small talk) 
    while preserving deterministic SOC playbook routing.
    """
    q_clean = user_query.lower().strip()
    
    # -------------------------------------------------------------------------
    # EDGE CASE 1: CONVERSATIONAL GREETINGS
    # -------------------------------------------------------------------------
    greetings = ['hi', 'hello', 'hey', 'greetings', 'good morning', 'good afternoon', 'anybody there']
    if any(q_clean == g or q_clean.startswith(g + " ") for g in greetings):
        return (
            "👋 **Welcome to the SOC Tactical Intel Interface.**\n\n"
            "I am your local AI Security Analyst. I am currently monitoring the live network feed.\n"
            "How can I assist you with threat remediation today? You can query me about "
            "**Portscans**, **DDoS attacks**, **Phishing URLs**, or **Malware strains**."
        )

    # -------------------------------------------------------------------------
    # EDGE CASE 2: GRATITUDE & CLOSURES
    # -------------------------------------------------------------------------
    thanks = ['thanks', 'thank you', 'ty', 'awesome', 'perfect', 'clear', 'bye', 'exit']
    if any(t in q_clean for t in thanks):
        return (
            "⚡ **Copy that.**\n\n"
            "Standing by for further indicators of compromise (IoCs). "
            "Maintain baseline security posture and keep monitoring the live pipeline feed."
        )

    # -------------------------------------------------------------------------
    # CORE TRACK 1: PORTSCAN ANALYSIS
    # -------------------------------------------------------------------------
    if "portscan" in q_clean or "port scan" in q_clean or "recon" in q_clean:
        return (
            "🛡️ **SOC Analyst Playbook - Portscan Detected:**\n\n"
            "**Analysis:** An external asset is executing sequential TCP/UDP SYN connections to map open service ports.\n"
            "**Immediate Action Items:**\n"
            "1. Identify the source IP and implement a temporary boundary block on your perimeter firewall.\n"
            "2. Audit target hosts for exposed legacy services (e.g., SSH/RDP).\n"
            "3. Enable rate-limiting thresholds across your network edge switches."
        )
        
    # -------------------------------------------------------------------------
    # CORE TRACK 2: DDOS / DOS ANALYSIS
    # -------------------------------------------------------------------------
    elif "ddos" in q_clean or "dos" in q_clean or "hulk" in q_clean or "flood" in q_clean:
        return (
            "🛡️ **SOC Analyst Playbook - Denial of Service (DoS/DDoS):**\n\n"
            "**Analysis:** Network layers are experiencing massive packet volume ingestion, exhausting connection pool states.\n"
            "**Immediate Action Items:**\n"
            "1. Engage your upstream Internet Service Provider (ISP) to activate Null-Routing scrubbing centers.\n"
            "2. Enable aggressive connection timeout thresholds on core load balancers.\n"
            "3. Restrict HTTP keep-alive allocations to protect internal server threads."
        )
        
    # -------------------------------------------------------------------------
    # CORE TRACK 3: PHISHING / URL ANALYSIS
    # -------------------------------------------------------------------------
    elif "phish" in q_clean or "url" in q_clean or "link" in q_clean or "domain" in q_clean:
        return (
            "🛡️ **SOC Analyst Playbook - Phishing Link Vector:**\n\n"
            "**Analysis:** Inbound email headers or links contain suspicious, non-standard domain mappings spoofing trusted domains.\n"
            "**Immediate Action Items:**\n"
            "1. Block the malicious domain parameter on your central Secure Email Gateway (SEG).\n"
            "2. Blacklist the destination URL across your corporate DNS servers.\n"
            "3. Check email proxy access logs to see if any user accounts successfully clicked the link."
        )
        
    # -------------------------------------------------------------------------
    # CORE TRACK 4: MALWARE CLASSIFICATION
    # -------------------------------------------------------------------------
    elif "malware" in q_clean or "mirai" in q_clean or "gafgyt" in q_clean or "rat" in q_clean or "virus" in q_clean:
        return (
            "🛡️ **SOC Analyst Playbook - Malicious Executable Analysis:**\n\n"
            "**Analysis:** Binary static characteristics match signature frameworks associated with active Trojan/Botnet families.\n"
            "**Immediate Action Items:**\n"
            "1. Isolate the infected endpoint from the VLAN instantly to halt lateral movement.\n"
            "2. Extract memory dumps and hash the binary for local EDR endpoint blocklists.\n"
            "3. Force an immediate system-wide credential reset for the affected endpoint machine."
        )

    # -------------------------------------------------------------------------
    # FALLBACK: UNKNOWN OR COMPLEX CYBER STRATEGY QUERIES
    # -------------------------------------------------------------------------
    fallbacks = [
        "🛡️ **SOC Analyst Response:**\n\nTo safely secure this threat vector, implement an explicit-deny firewall rule policy, verify Endpoint Detection and Response (EDR) agents are fully updated, and isolate the affected subnet segments immediately.",
        
        "🛡️ **SOC Analyst Response:**\n\nSecurity best practices require reviewing your Active Directory access logs for signs of credential dumping, checking your perimeter firewalls for unauthorized outbound connections, and blocking the suspicious indicators of compromise (IoCs).",
        
        "🛡️ **SOC Analyst Response:**\n\nRecommended mitigation matrix: Verify your server patch levels against known exploits, check internal network traffic for lateral scanning anomalies, and ensure Multi-Factor Authentication (MFA) is strictly enforced on all access points."
    ]
    
    return random.choice(fallbacks)