"""
Linux Log Collector for MiniSIEM X
Parses authentication logs (e.g., /var/log/auth.log, /var/log/secure), SSH logins, and sudo activity.
"""
import re
from typing import List, Dict, Any
from backend.collectors.base_collector import BaseCollector

class LinuxCollector(BaseCollector):
    def __init__(self):
        super().__init__(name="Linux Collector", source_type="LINUX")

    def collect(self, raw_input: Any) -> List[Dict[str, Any]]:
        """Parses Linux syslog / auth.log entries into standardized raw records."""
        events: List[Dict[str, Any]] = []
        if isinstance(raw_input, list):
            lines = raw_input
        elif isinstance(raw_input, str):
            lines = raw_input.splitlines()
        else:
            return events

        for line in lines:
            line_str = str(line).strip()
            if not line_str:
                continue

            parsed_event = self._parse_line(line_str)
            if parsed_event:
                events.append(parsed_event)

        return events

    def _parse_line(self, line: str) -> Dict[str, Any]:
        # Failed SSH password regex
        # e.g.: Nov 24 10:15:02 web-gateway sshd[1234]: Failed password for invalid user admin from 198.51.100.24 port 45231 ssh2
        ssh_failed_match = re.search(
            r"sshd\[\d+\]:\s+Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)",
            line, re.IGNORECASE
        )
        if ssh_failed_match:
            username = ssh_failed_match.group(1)
            source_ip = ssh_failed_match.group(2)
            dest_port = int(ssh_failed_match.group(3))
            return {
                "source": "linux",
                "event_type": "auth_failure",
                "username": username,
                "source_ip": source_ip,
                "destination_port": dest_port,
                "severity": "HIGH",
                "raw_event": line,
                "metadata": {"service": "sshd", "auth_status": "failed"}
            }

        # Accepted SSH password regex
        # e.g.: Nov 24 10:17:30 web-gateway sshd[1234]: Accepted password for admin from 198.51.100.24 port 45231 ssh2
        ssh_accepted_match = re.search(
            r"sshd\[\d+\]:\s+Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)",
            line, re.IGNORECASE
        )
        if ssh_accepted_match:
            username = ssh_accepted_match.group(1)
            source_ip = ssh_accepted_match.group(2)
            dest_port = int(ssh_accepted_match.group(3))
            return {
                "source": "linux",
                "event_type": "auth_success",
                "username": username,
                "source_ip": source_ip,
                "destination_port": dest_port,
                "severity": "INFO",
                "raw_event": line,
                "metadata": {"service": "sshd", "auth_status": "success"}
            }

        # sudo command execution / privilege elevation
        # e.g.: Nov 24 10:18:15 web-gateway sudo:   admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash
        sudo_match = re.search(
            r"sudo:\s+(\S+)\s+:.*?USER=(\S+)\s+;.*?COMMAND=(.*)",
            line, re.IGNORECASE
        )
        if sudo_match:
            user = sudo_match.group(1)
            target_user = sudo_match.group(2)
            command = sudo_match.group(3).strip()
            return {
                "source": "linux",
                "event_type": "privilege_escalation" if target_user == "root" else "privilege_change",
                "username": user,
                "severity": "HIGH" if target_user == "root" else "MEDIUM",
                "raw_event": line,
                "metadata": {"elevated_user": target_user, "command": command}
            }

        # Fallback generic Linux event
        return {
            "source": "linux",
            "event_type": "system_event",
            "severity": "INFO",
            "raw_event": line
        }

