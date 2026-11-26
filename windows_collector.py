"""
MiniSIEM X Real-Time Windows Security Event Log Collector
Uses built-in Windows `wevtutil` to read real Security Event Log events:
  - 4624: Successful logon
  - 4625: Failed logon
  - 4672: Special privileges assigned

Forwards new events continuously to the MiniSIEM X backend API without duplicates.
"""
import argparse
import ctypes
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import deque
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from backend.collectors.windows_collector import WindowsCollector

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_STATE_FILE = BASE_DIR / "data" / "windows_collector_state.json"
DEFAULT_API_URL = os.getenv("MINISIEM_API_URL", "http://127.0.0.1:8000")
TARGET_EVENT_IDS = "(EventID=4624 or EventID=4625 or EventID=4672)"


def is_windows_admin() -> bool:
    """Checks if the current Windows process has Administrator privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def load_state(state_file: Path) -> Dict[str, Any]:
    """Loads persisted EventRecordID checkpoint so restarts do not re-send old events."""
    if not state_file.exists():
        return {"last_record_id": None}
    try:
        with state_file.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
            if isinstance(data, dict):
                return data
    except Exception as exc:
        print(f"[!] Warning: Could not read state file ({exc}). Starting fresh checkpoint.")
    return {"last_record_id": None}


def save_state(state_file: Path, last_record_id: Optional[int]) -> None:
    """Persists the latest processed EventRecordID safely."""
    state_file.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = state_file.with_suffix(".tmp")
    with tmp_path.open("w", encoding="utf-8") as fh:
        json.dump({"last_record_id": last_record_id}, fh, indent=2)
    tmp_path.replace(state_file)


def run_wevtutil(args: List[str]) -> Tuple[bool, str, str]:
    """Executes built-in Windows `wevtutil` and returns (ok, stdout, error_message)."""
    try:
        proc = subprocess.run(
            ["wevtutil", *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
    except FileNotFoundError:
        return False, "", "wevtutil.exe was not found. This collector requires Windows."
    except subprocess.TimeoutExpired:
        return False, "", "Timed out while querying the Windows Security Event Log."
    except Exception as exc:
        return False, "", f"Failed to execute wevtutil: {exc}"

    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "Unknown wevtutil error").strip()
        return False, "", err
    return True, proc.stdout, ""


def get_latest_security_record_id() -> Optional[int]:
    """Returns the highest EventRecordID currently in the Windows Security log."""
    ok, stdout, _ = run_wevtutil(["qe", "Security", "/c:1", "/rd:true", "/f:xml", "/e:Events"])
    if not ok or not stdout.strip():
        return None
    import re
    match = re.search(r"<EventRecordID>(\d+)</EventRecordID>", stdout)
    return int(match.group(1)) if match else None


def fetch_security_events(
    collector: WindowsCollector,
    last_record_id: Optional[int],
    lookback: int,
    include_system: bool,
) -> Tuple[bool, List[Dict[str, Any]], Optional[int], str]:
    """
    Queries Windows Security Event Log for 4624/4625/4672 events.
    Returns (ok, events, new_max_record_id, error_message).
    """
    if last_record_id is None:
        query = f"*[System[{TARGET_EVENT_IDS}]]"
        args = ["qe", "Security", f"/q:{query}", "/f:xml", "/rd:true", f"/c:{lookback}", "/e:Events"]
    else:
        query = f"*[System[{TARGET_EVENT_IDS} and EventRecordID>{last_record_id}]]"
        args = ["qe", "Security", f"/q:{query}", "/f:xml", "/c:100", "/e:Events"]

    ok, xml_out, err = run_wevtutil(args)
    if not ok:
        return False, [], last_record_id, err

    # Extract max EventRecordID seen in XML (even if all events were OS noise)
    import re
    record_ids = [int(m) for m in re.findall(r"<EventRecordID>(\d+)</EventRecordID>", xml_out)]
    max_id = max(record_ids) if record_ids else last_record_id
    if last_record_id is None:
        tip_id = get_latest_security_record_id()
        if tip_id is not None:
            max_id = max(max_id or 0, tip_id)

    events = collector.parse_windows_xml(xml_out, include_system=include_system)
    if last_record_id is None:
        # Initial lookback was queried newest-first (/rd:true); restore chronological order
        events.reverse()

    return True, events, max_id, ""


def post_events_to_backend(api_url: str, events: List[Dict[str, Any]], timeout: int = 10) -> Tuple[bool, Dict[str, Any], str]:
    """Sends a batch of parsed Windows events to MiniSIEM X `/api/logs/batch`."""
    endpoint = f"{api_url.rstrip('/')}/api/logs/batch"
    payload = json.dumps({"events": events, "source_name": "windows"}).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            data = json.loads(body) if body else {}
            return True, data, ""
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        return False, {}, f"Backend returned HTTP {exc.code}: {detail}"
    except urllib.error.URLError as exc:
        return False, {}, f"Cannot connect to MiniSIEM X backend at {api_url} ({exc.reason}). Is the backend running?"
    except Exception as exc:
        return False, {}, f"Unexpected error sending events to backend: {exc}"


def check_backend_health(api_url: str) -> Tuple[bool, str]:
    """Verifies that the MiniSIEM X backend is reachable before streaming."""
    endpoint = f"{api_url.rstrip('/')}/health"
    try:
        with urllib.request.urlopen(endpoint, timeout=5) as resp:
            if resp.status == 200:
                return True, ""
            return False, f"Unexpected status code {resp.status}"
    except Exception as exc:
        return False, f"Cannot reach MiniSIEM X backend at {api_url} ({exc})"


def print_permission_help(error_msg: str) -> None:
    """Prints clear, beginner-friendly instructions when Security log access is denied."""
    print("\n" + "=" * 68)
    print(" [!] PERMISSION DENIED: Cannot read Windows Security Event Log")
    print("=" * 68)
    print(f" Details: {error_msg}\n")
    print(" Windows restricts the Security Event Log to Administrators.")
    print(" To collect real 4624 / 4625 / 4672 events from this computer:")
    print("   1. Right-click 'start_collector.bat' -> 'Run as administrator'")
    print("      OR open PowerShell / Terminal as Administrator and run:")
    print("        .\\start_collector.ps1")
    print("   2. Optional one-time grant for standard user:")
    print('        net localgroup "Event Log Readers" "%USERNAME%" /add')
    print("      (Sign out and sign back in after running that command.)")
    print("=" * 68 + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="MiniSIEM X Windows Security Event Log Collector")
    parser.add_argument("--url", default=DEFAULT_API_URL, help="MiniSIEM X backend base URL (default: http://127.0.0.1:8000)")
    parser.add_argument("--interval", type=float, default=3.0, help="Polling interval in seconds (default: 3.0)")
    parser.add_argument("--lookback", type=int, default=20, help="Recent matching events to read on first run (default: 20)")
    parser.add_argument("--include-system", action="store_true", help="Include noisy built-in SYSTEM/DWM/UMFD accounts")
    parser.add_argument("--once", action="store_true", help="Run a single collection pass and exit")
    parser.add_argument("--reset-state", action="store_true", help="Reset saved EventRecordID checkpoint")
    parser.add_argument("--state-file", default=str(DEFAULT_STATE_FILE), help="Path to collector checkpoint file")
    args = parser.parse_args()

    state_file = Path(args.state_file)
    if args.reset_state and state_file.exists():
        state_file.unlink()
        print(f"[*] Cleared checkpoint state: {state_file}")

    print("=" * 64)
    print("  MiniSIEM X - Windows Security Event Log Collector")
    print("  Monitoring Event IDs: 4624 (Success), 4625 (Failure), 4672 (Privs)")
    print("=" * 64)
    print(f"[*] Backend Target : {args.url}")
    print(f"[*] Poll Interval  : {args.interval}s")
    print(f"[*] Admin Privilege: {'YES' if is_windows_admin() else 'NO (may fail unless in Event Log Readers)'}")

    healthy, health_err = check_backend_health(args.url)
    if healthy:
        print("[+] Backend API connection verified (HEALTHY).")
    else:
        print(f"[!] Warning: {health_err}")
        print("[!] Will keep retrying until backend is started...")

    collector = WindowsCollector()
    state = load_state(state_file)
    last_record_id: Optional[int] = state.get("last_record_id")
    seen_ids: deque = deque(maxlen=1000)
    seen_set = set()
    pending_events: List[Dict[str, Any]] = []
    pending_max_id: Optional[int] = last_record_id

    if last_record_id is not None:
        print(f"[*] Resuming from saved EventRecordID > {last_record_id}")
    else:
        print(f"[*] First run: collecting up to {args.lookback} recent Security events (4624/4625/4672)...")

    try:
        while True:
            # 1. Read any newly arrived Windows events if queue is empty
            if not pending_events:
                ok, new_events, max_id, err = fetch_security_events(
                    collector=collector,
                    last_record_id=last_record_id,
                    lookback=args.lookback,
                    include_system=args.include_system,
                )
                if not ok:
                    if "access is denied" in err.lower():
                        print_permission_help(err)
                        return 1
                    print(f"[!] Error reading Windows Security log: {err}")
                    if args.once:
                        return 1
                    time.sleep(max(args.interval, 5.0))
                    continue

                # Belt-and-suspenders deduplication by EventRecordID
                unique_events = []
                for ev in new_events:
                    rec_id = ev.get("metadata", {}).get("EventRecordID")
                    if rec_id is not None:
                        if rec_id in seen_set:
                            continue
                        if len(seen_ids) == seen_ids.maxlen:
                            oldest = seen_ids.popleft()
                            seen_set.discard(oldest)
                        seen_ids.append(rec_id)
                        seen_set.add(rec_id)
                    unique_events.append(ev)

                if unique_events:
                    pending_events = unique_events
                    pending_max_id = max_id
                elif max_id is not None and max_id != last_record_id:
                    # Advance checkpoint when only filtered OS-noise events occurred
                    last_record_id = max_id
                    save_state(state_file, last_record_id)

            # 2. Forward pending events to MiniSIEM X backend
            if pending_events:
                sent_ok, resp_data, post_err = post_events_to_backend(args.url, pending_events)
                if sent_ok:
                    ingested = resp_data.get("total_ingested", len(pending_events))
                    alerts_triggered = resp_data.get("alerts_triggered", 0)
                    for ev in pending_events:
                        ev_id = ev.get("metadata", {}).get("EventID", "?")
                        user = ev.get("username") or "-"
                        ip = ev.get("source_ip") or "Local"
                        print(f"[+] Event {ev_id} ({ev['event_type']}) | user={user} | ip={ip} | host={ev.get('hostname')}")
                    msg = f"[->] Forwarded {ingested} real Windows event(s) to MiniSIEM X."
                    if alerts_triggered:
                        msg += f" [ALERT TRIGGERED: {alerts_triggered}]"
                    print(msg)

                    pending_events = []
                    if pending_max_id is not None:
                        last_record_id = pending_max_id
                        save_state(state_file, last_record_id)
                else:
                    print(f"[!] {post_err} (Keeping {len(pending_events)} event(s) queued; retrying in 5s)")
                    if args.once:
                        return 1
                    time.sleep(5.0)
                    continue

            if args.once:
                print("[*] Single pass complete.")
                return 0

            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\n[*] Collector stopped by user.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
