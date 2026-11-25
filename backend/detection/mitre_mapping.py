"""
MITRE ATT&CK Mapping Module for MiniSIEM X
Maps detection rules and observed telemetry to official MITRE ATT&CK techniques.
"""
from typing import Dict, Any, Optional

MITRE_TECHNIQUES: Dict[str, Dict[str, Any]] = {
    "T1110": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "sub_techniques": ["T1110.001: Password Guessing", "T1110.003: Password Spraying"],
        "description": "Adversaries may use brute force techniques to attempt authentication credentials by systematically guessing passwords.",
        "url": "https://attack.mitre.org/techniques/T1110/",
        "mitigation": "Enforce account lockouts after consecutive failed logins, multi-factor authentication, and IP-based rate limiting."
    },
    "T1078": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Initial Access",
        "sub_techniques": ["T1078.001: Default Accounts", "T1078.003: Local Accounts"],
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
        "url": "https://attack.mitre.org/techniques/T1078/",
        "mitigation": "Audit account logins, restrict administrative logins to known jump hosts, and monitor for impossible travel or unusual IP logins."
    },
    "T1046": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "sub_techniques": [],
        "description": "Adversaries may attempt to get a listing of services running on hosts by scanning ports across network boundaries.",
        "url": "https://attack.mitre.org/techniques/T1046/",
        "mitigation": "Deploy network intrusion detection, block unnecessary ingress ports at perimeter firewalls, and alert on horizontal/vertical port sweeps."
    },
    "T1548": {
        "technique_id": "T1548",
        "technique_name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "sub_techniques": ["T1548.003: Sudo and Sudo Caching"],
        "description": "Adversaries may circumvent mechanisms designed to control elevation of privileges to gain higher-level permissions.",
        "url": "https://attack.mitre.org/techniques/T1548/",
        "mitigation": "Restrict sudoers configuration, enforce password re-entry for sensitive binaries, and log all elevated commands."
    },
    "T1059": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "sub_techniques": ["T1059.004: Unix Shell", "T1059.001: PowerShell"],
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
        "url": "https://attack.mitre.org/techniques/T1059/",
        "mitigation": "Enable process command-line auditing, enforce script execution policies, and restrict shell execution environments."
    }
}

def get_mitre_mapping(technique_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves MITRE ATT&CK reference data for a given technique ID."""
    return MITRE_TECHNIQUES.get(technique_id)

def get_all_mitre_mappings() -> Dict[str, Dict[str, Any]]:
    """Returns the full MITRE catalog used across MiniSIEM X detection rules."""
    return MITRE_TECHNIQUES

