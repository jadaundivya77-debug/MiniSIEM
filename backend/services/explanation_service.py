"""
Explainable Alert & AI Security Assistant Service for MiniSIEM X
Generates deterministic, evidence-based explanations for every alert and incident.
Includes a local deterministic explanation engine and an extensible LLM adapter.
"""
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from backend.models import Incident, Alert, LogEvent
from backend.detection.mitre_mapping import get_mitre_mapping

def generate_alert_explanation(data: Dict[str, Any]) -> str:
    """
    Generates a structured, transparent explanation based directly on actual telemetry:
    - What happened?
    - Why is it suspicious?
    - Which rule was triggered?
    - Who and which IPs were involved?
    - Evidence summary.
    """
    rule_id = data.get("rule_id", "UNKNOWN")
    src_ip = data.get("source_ip", "Unknown IP")
    user = data.get("target_username") or "Unspecified account"
    ev = data.get("evidence", {})
    window = data.get("time_window_seconds", 120)

    if rule_id == "RULE-001":
        failed_count = ev.get("failed_attempts", data.get("event_count", 5))
        return (
            f"WHAT HAPPENED:\n"
            f"{failed_count} consecutive failed authentication attempts were detected targeting account '{user}' from source IP {src_ip}.\n\n"
            f"WHY IS IT SUSPICIOUS:\n"
            f"The rapid failure rate exceeds normal user typographical error thresholds (limit: {ev.get('threshold', 5)} attempts within {window}s). "
            f"This behavior strongly matches automated password guessing or credential stuffing dictionary attacks.\n\n"
            f"TRIGGERED RULE:\n"
            f"{data.get('rule_name')} ({rule_id}) | MITRE ATT&CK: T1110 (Brute Force).\n\n"
            f"EVIDENCE SUMMARY:\n"
            f"• Source IP: {src_ip}\n"
            f"• Target Username: {user}\n"
            f"• Total Failed Attempts: {failed_count}\n"
            f"• Observed Window: {window} seconds"
        )

    elif rule_id == "RULE-002":
        return (
            f"WHAT HAPPENED:\n"
            f"A successful login to account '{user}' was established from untrusted IP address {src_ip}.\n\n"
            f"WHY IS IT SUSPICIOUS:\n"
            f"The originating IP address is not present in the organization's configured internal or trusted whitelist. "
            f"While this may represent remote worker access or travel, unverified external logins warrant verification to rule out session hijacking.\n\n"
            f"TRIGGERED RULE:\n"
            f"{data.get('rule_name')} ({rule_id}) | MITRE ATT&CK: T1078 (Valid Accounts).\n\n"
            f"EVIDENCE SUMMARY:\n"
            f"• Source IP: {src_ip} (Non-whitelisted external origin)\n"
            f"• Authenticated User: {user}\n"
            f"• Host/Asset: {data.get('affected_asset')}"
        )

    elif rule_id == "RULE-003":
        ports = ev.get("unique_ports_scanned", [])
        port_count = ev.get("total_ports_count", len(ports))
        ports_display = ", ".join(str(p) for p in ports[:12])
        if len(ports) > 12:
            ports_display += f" ... (+{len(ports)-12} more)"
        return (
            f"WHAT HAPPENED:\n"
            f"A vertical or horizontal network port sweep was detected from {src_ip}, probing {port_count} distinct ports within {window}s.\n\n"
            f"WHY IS IT SUSPICIOUS:\n"
            f"Standard client applications do not sequentially probe dozens of service ports. This pattern is characteristic of automated scanning utilities (e.g. Nmap, Masscan) performing target reconnaissance.\n\n"
            f"TRIGGERED RULE:\n"
            f"{data.get('rule_name')} ({rule_id}) | MITRE ATT&CK: T1046 (Network Service Discovery).\n\n"
            f"EVIDENCE SUMMARY:\n"
            f"• Offending Host: {src_ip}\n"
            f"• Distinct Ports Probed: {port_count} (Ports: {ports_display})\n"
            f"• Observation Interval: {window} seconds"
        )

    elif rule_id == "RULE-004":
        reason = ev.get("detection_reason", "Administrative elevation command executed.")
        return (
            f"WHAT HAPPENED:\n"
            f"User '{user}' performed a privilege elevation on host '{data.get('affected_asset')}'.\n\n"
            f"WHY IS IT SUSPICIOUS:\n"
            f"{reason} Elevation of privileges provides root or SYSTEM level access, allowing attackers to disable security tools, dump credentials, or persist across reboots.\n\n"
            f"TRIGGERED RULE:\n"
            f"{data.get('rule_name')} ({rule_id}) | MITRE ATT&CK: T1548 (Abuse Elevation Control Mechanism).\n\n"
            f"EVIDENCE SUMMARY:\n"
            f"• User: {user}\n"
            f"• Target Host: {data.get('affected_asset')}\n"
            f"• Source IP: {src_ip}"
        )

    elif rule_id == "RULE-005":
        return (
            f"WHAT HAPPENED:\n"
            f"Correlated Account Takeover: Multiple authentication failures against '{user}' from {src_ip} were immediately followed by a successful login.\n\n"
            f"WHY IS IT SUSPICIOUS:\n"
            f"This sequence confirms that an attacker succeeded in guessing or cracking valid credentials after initial brute-force attempts. A critical threat to internal security boundaries.\n\n"
            f"TRIGGERED RULE:\n"
            f"{data.get('rule_name')} ({rule_id}) | MITRE ATT&CK: T1078 & T1110.\n\n"
            f"EVIDENCE SUMMARY:\n"
            f"• Multi-Stage Attack Chain: Brute-Force -> Valid Session -> Compromise\n"
            f"• Offending IP: {src_ip}\n"
            f"• Compromised Account: {user}"
        )

    return f"Security alert triggered by detection rule {rule_id} for asset {data.get('affected_asset')}."

def get_investigation_recommendations(rule_id: str) -> str:
    """Returns standardized SOP (Standard Operating Procedure) steps for analysts."""
    recs = {
        "RULE-001": (
            "1. Review target account login history to confirm if any attempt succeeded.\n"
            "2. Verify whether source IP belongs to an authorized remote employee or VPN.\n"
            "3. If unauthorized, temporarily block the offending IP address at the edge firewall.\n"
            "4. Enforce mandatory password reset and verify MFA registration for the account."
        ),
        "RULE-002": (
            "1. Contact user out-of-band (e.g. phone/Slack) to verify whether they initiated this login.\n"
            "2. Check geolocation and ASN metadata of the source IP.\n"
            "3. If legitimate business activity, add IP to Trusted IP Whitelist.\n"
            "4. If unconfirmed, terminate active sessions immediately and revoke access tokens."
        ),
        "RULE-003": (
            "1. Identify whether any destination ports on the target host were open and responded.\n"
            "2. Correlate with firewall drop/reject logs for the source IP.\n"
            "3. Implement temporary perimeter shun/drop rule for the scanning IP.\n"
            "4. Verify that non-essential ports on target servers are closed."
        ),
        "RULE-004": (
            "1. Inspect the command line arguments and binaries executed with elevated privileges.\n"
            "2. Cross-reference with scheduled maintenance or approved IT change requests.\n"
            "3. Verify file integrity and hashes of modified configuration files.\n"
            "4. If unauthorized, isolate the affected host from the internal network immediately."
        ),
        "RULE-005": (
            "1. IMMEDIATELY revoke all active authentication sessions and change password.\n"
            "2. Isolate the affected host endpoint from the corporate network.\n"
            "3. Review subsequent telemetry for persistence mechanisms (cron jobs, new users, registry keys).\n"
            "4. Export forensic timeline and escalate to Incident Response Commander."
        )
    }
    return recs.get(rule_id, "1. Review related event logs.\n2. Confirm authorization.\n3. Escalate if malicious.")

class LocalDeterministicAssistant:
    """
    Local AI Security Assistant Engine.
    Operates without paid APIs or external dependencies.
    Provides verified evidence, rule conclusions, and actionable containment guidance.
    """
    @classmethod
    def query(cls, message: str, context_type: Optional[str], context_id: Optional[str | int], db: Session) -> Dict[str, Any]:
        msg_lower = message.lower()
        verified_evidence: List[str] = []
        rule_conclusions: List[str] = []
        ai_recommendations: List[str] = []

        # If context is an Incident
        if context_type == "incident" and context_id:
            incident = db.query(Incident).filter(
                (Incident.id == int(context_id)) | (Incident.incident_number == str(context_id))
            ).first()
            if incident:
                verified_evidence.append(f"Incident: {incident.incident_number} - {incident.title}")
                verified_evidence.append(f"Severity: {incident.severity} | Current Status: {incident.status}")
                if incident.attack_story:
                    verified_evidence.append(f"Correlated Timeline: {incident.attack_story}")

                rule_conclusions.append(f"Root Cause: {incident.root_cause or 'Multi-stage authentication compromise'}")
                rule_conclusions.append(f"Associated MITRE Tactic: {incident.mitre_tactic or 'Initial Access'}")

                ai_recommendations.append("Execute containment playbook: Isolate host and invalidate credentials.")
                ai_recommendations.append("Conduct memory and persistent artifact analysis on affected assets.")
                ai_recommendations.append("Update firewall rules to permanently blacklist offending IPs.")

                reply = (
                    f"### MiniSIEM X Security Assistant: Incident Analysis\n\n"
                    f"**Incident Overview:** {incident.title} ({incident.incident_number})\n\n"
                    f"**Telemetry Summary:**\n"
                    f"{incident.description}\n\n"
                    f"**Attack Story:**\n{incident.attack_story or 'No chronological story generated yet.'}\n\n"
                    f"**Recommended Analyst Action Plan:**\n"
                    f"1. Isolate the involved host to prevent lateral movement.\n"
                    f"2. Terminate active user sessions.\n"
                    f"3. Mark incident as INVESTIGATING while preserving raw log evidence."
                )
                return {
                    "reply": reply,
                    "verified_evidence": verified_evidence,
                    "rule_conclusions": rule_conclusions,
                    "ai_recommendations": ai_recommendations,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }

        # If context is an Alert
        if context_type == "alert" and context_id:
            alert = db.query(Alert).filter(Alert.id == int(context_id)).first()
            if alert:
                verified_evidence.append(f"Alert ID: {alert.id} | Rule: {alert.rule_name} ({alert.rule_id})")
                verified_evidence.append(f"Source IP: {alert.source_ip} | User: {alert.target_username}")
                verified_evidence.append(f"Event Count: {alert.event_count} across {alert.time_window_seconds}s")

                rule_conclusions.append(f"Severity Assessment: {alert.severity}")
                rule_conclusions.append(f"MITRE Technique: {alert.mitre_technique_id} ({alert.mitre_technique_name})")

                ai_recommendations.append("Cross-reference source IP in Threat Intelligence tab.")
                ai_recommendations.append("Check for matching events on secondary log sources.")

                reply = (
                    f"### Alert Explanation: {alert.title}\n\n"
                    f"{alert.explanation or 'Alert generated by automated rule trigger.'}\n\n"
                    f"**Actionable Investigation Steps:**\n"
                    f"{alert.recommended_actions or 'Review raw events.'}"
                )
                return {
                    "reply": reply,
                    "verified_evidence": verified_evidence,
                    "rule_conclusions": rule_conclusions,
                    "ai_recommendations": ai_recommendations,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }

        # General SOC Assistance
        if "brute" in msg_lower or "password" in msg_lower:
            verified_evidence.append("Rule RULE-001 monitors failed logins (threshold: 5 attempts / 120s).")
            rule_conclusions.append("Brute force attacks target authentication services (SSH, RDP, Web).")
            ai_recommendations.append("Verify lockout policies and enable Multi-Factor Authentication.")
            reply = (
                "**Brute-Force Detection Guidance:**\n\n"
                "MiniSIEM X tracks failed authentication events across Linux SSH, Windows Logon (Event 4625), and Web API endpoints. "
                "When >= 5 failures occur for the same user/IP within 120s, a HIGH severity alert is raised. "
                "If immediately followed by a successful login, Rule RULE-005 automatically escalates to a CRITICAL Correlated Incident."
            )
        elif "port scan" in msg_lower or "nmap" in msg_lower or "recon" in msg_lower:
            verified_evidence.append("Rule RULE-003 detects sweeps across >= 10 unique ports within 60s.")
            rule_conclusions.append("Port scans represent pre-attack reconnaissance to map exposed services.")
            ai_recommendations.append("Implement automated firewall shun policies for repetitive scanners.")
            reply = (
                "**Port Scan Reconnaissance Overview:**\n\n"
                "MiniSIEM X correlates destination ports targeted from the same source IP. Probing 10 or more ports within 60 seconds triggers a MEDIUM severity alert under MITRE T1046 (Network Service Discovery)."
            )
        elif "report" in msg_lower or "draft" in msg_lower or "summary" in msg_lower:
            total_events = db.query(LogEvent).count()
            total_alerts = db.query(Alert).count()
            open_incidents = db.query(Incident).filter(Incident.status == "OPEN").count()
            reply = (
                f"### Executive Security Briefing\n\n"
                f"• **Telemetry Intake:** {total_events} events processed.\n"
                f"• **Active Alerts:** {total_alerts} security alerts triggered.\n"
                f"• **Open Incidents:** {open_incidents} incidents awaiting analyst triage.\n\n"
                f"**SOC Posture Assessment:** The threat detection pipeline is actively monitoring all registered sources. "
                f"Navigate to the **Reports** section to export full compliance summaries in CSV or print format."
            )
        else:
            reply = (
                "Hello, Analyst. I am your MiniSIEM X Security Assistant. "
                "I analyze live telemetry, explain why alerts were generated, trace multi-stage attack stories, "
                "and recommend mitigation steps. How can I assist your investigation?"
            )

        return {
            "reply": reply,
            "verified_evidence": verified_evidence,
            "rule_conclusions": rule_conclusions,
            "ai_recommendations": ai_recommendations,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

