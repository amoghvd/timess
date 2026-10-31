#!/usr/bin/env python3
"""Synthetic EDR (Endpoint Detection & Response) Log Generator.

Generates realistic enterprise endpoint telemetry (processes, network, files,
credentials, registry) interleaved with multi-stage attack kill chains.
"""
import argparse
import json
import os
import random
import sys
import time
from datetime import datetime, timedelta, timezone

USERS = ["alice.smith", "bob.jones", "carol.white", "david.kim", "emma.davis", "frank.miller"]
ADMIN_USERS = ["SYSTEM", "admin_backup", "domain_admin", "svc_backup"]
HOSTS = ["WS-001.corp.local", "WS-002.corp.local", "WS-003.corp.local", "LAPTOP-DEV.corp.local", "HR-PC-01.corp.local"]
SERVERS = ["DC-01.corp.local", "FILESERVER-01.corp.local", "APP-SRV-01.corp.local", "DB-PROD-01.corp.local"]
INTERNAL_IPS = ["192.168.1.10", "192.168.1.25", "192.168.1.42", "192.168.1.105", "192.168.1.110"]
EXTERNAL_IPS = ["203.0.113.42", "198.51.100.88", "185.220.101.5", "91.108.4.12", "142.250.190.46"]

BENIGN_PROCESSES = [
    ("chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "explorer.exe", "Low"),
    ("teams.exe", "C:\\Users\\%USER%\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe", "explorer.exe", "Low"),
    ("outlook.exe", "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "explorer.exe", "Low"),
    ("slack.exe", "C:\\Users\\%USER%\\AppData\\Local\\slack\\slack.exe", "explorer.exe", "Low"),
    ("svchost.exe", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p", "services.exe", "Low"),
    ("SearchIndexer.exe", "C:\\Windows\\system32\\SearchIndexer.exe /Embedding", "services.exe", "Low"),
    ("OneDrive.exe", "C:\\Users\\%USER%\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe /background", "explorer.exe", "Low"),
    ("code.exe", "C:\\Users\\%USER%\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe", "explorer.exe", "Low"),
]

BENIGN_ACTIONS = [
    ("ProcessCreate", "Process started: {proc}", "Low"),
    ("NetworkConnect", "Outbound HTTPS connection to {dst_ip}:443 via {proc}", "Low"),
    ("FileCreate", "File created in AppData\\Local\\Temp by {proc}", "Low"),
    ("DnsQuery", "DNS query resolved for internal.portal.corp via {proc}", "Low"),
    ("AuthSuccess", "Kerberos authentication ticket granted for user {user}", "Low"),
    ("RegistrySet", "Registry key HKCU\\Software\\Microsoft\\Office set by {proc}", "Low"),
]

ATTACK_SCENARIOS = [
    {
        "host": "WS-001.corp.local",
        "user": "alice.smith",
        "ip": "192.168.1.105",
        "source": "EDR-Network",
        "action": "Vulnerability Scanning",
        "detail": "Active port scan and vulnerability probing against internal subnet 192.168.1.0/24",
        "stage": "Reconnaissance",
        "technique": "T1595.002",
        "severity": "Medium",
    },
    {
        "host": "WS-001.corp.local",
        "user": "alice.smith",
        "ip": "192.168.1.105",
        "source": "EDR-Email",
        "action": "Phishing: Spearphishing Attachment",
        "detail": "Phishing email opened with quarterly_invoice.xlsm malicious attachment",
        "stage": "Initial Access",
        "technique": "T1566.001",
        "severity": "High",
    },
    {
        "host": "WS-001.corp.local",
        "user": "alice.smith",
        "ip": "192.168.1.105",
        "source": "EDR-Process",
        "action": "Malicious File",
        "detail": "Malicious macro executed via excel.exe spawning child powershell.exe -w hidden -enc",
        "stage": "Execution",
        "technique": "T1204.002",
        "severity": "High",
    },
    {
        "host": "WS-001.corp.local",
        "user": "alice.smith",
        "ip": "192.168.1.105",
        "source": "EDR-Kernel",
        "action": "Exploitation for Privilege Escalation",
        "detail": "Privilege escalation detected: CVE exploit token elevation from user to SYSTEM",
        "stage": "Privilege Escalation",
        "technique": "T1068",
        "severity": "Critical",
    },
    {
        "host": "WS-001.corp.local",
        "user": "SYSTEM",
        "ip": "192.168.1.105",
        "source": "EDR-Memory",
        "action": "LSASS Memory",
        "detail": "Credential dump detected: unauthorized lsass.exe process memory read via Mimikatz",
        "stage": "Credential Access",
        "technique": "T1003.001",
        "severity": "Critical",
    },
    {
        "host": "WS-001.corp.local",
        "user": "admin_backup",
        "ip": "192.168.1.105",
        "source": "EDR-Task",
        "action": "Scheduled Task",
        "detail": "Scheduled task created for persistence: WindowsUpdateBackdoor running every 4 hours",
        "stage": "Persistence",
        "technique": "T1053.005",
        "severity": "High",
    },
    {
        "host": "FILESERVER-01.corp.local",
        "user": "admin_backup",
        "ip": "192.168.1.105",
        "source": "EDR-Network",
        "action": "SMB/Windows Admin Shares",
        "detail": "SMB lateral movement session established to C$ admin share on FILESERVER-01",
        "stage": "Lateral Movement",
        "technique": "T1021.002",
        "severity": "Critical",
    },
    {
        "host": "FILESERVER-01.corp.local",
        "user": "admin_backup",
        "ip": "192.168.1.20",
        "source": "EDR-Network",
        "action": "Web Protocols",
        "detail": "Periodic command and control C2 beacon detected outbound to external IP 185.220.101.5",
        "stage": "Command and Control",
        "technique": "T1071.001",
        "severity": "High",
    },
    {
        "host": "FILESERVER-01.corp.local",
        "user": "admin_backup",
        "ip": "192.168.1.20",
        "source": "EDR-File",
        "action": "Archive Collected Data",
        "detail": "Confidential customer database records files staged into password-protected archive",
        "stage": "Collection",
        "technique": "T1560",
        "severity": "High",
    },
    {
        "host": "FILESERVER-01.corp.local",
        "user": "admin_backup",
        "ip": "192.168.1.20",
        "source": "EDR-Network",
        "action": "Exfiltration Over Alternative Protocol",
        "detail": "Large data upload to an outside IP 185.220.101.5 (2.4 GB transferred)",
        "stage": "Exfiltration",
        "technique": "T1048",
        "severity": "Critical",
    },
    {
        "host": "FILESERVER-01.corp.local",
        "user": "admin_backup",
        "ip": "192.168.1.20",
        "source": "EDR-EventLog",
        "action": "Indicator Removal",
        "detail": "Security event logs cleared with wevtutil cl Security to evade detection",
        "stage": "Defense Evasion",
        "technique": "T1070",
        "severity": "High",
    },
]


def generate_event(event_time, user, host, ip):
    proc_name, proc_path, parent, sev = random.choice(BENIGN_PROCESSES)
    action_type, detail_tpl, sev = random.choice(BENIGN_ACTIONS)
    dst_ip = random.choice(EXTERNAL_IPS if action_type == "NetworkConnect" else INTERNAL_IPS)
    detail = detail_tpl.format(proc=proc_name, dst_ip=dst_ip, user=user)

    return {
        "timestamp": event_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "time": event_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": host,
        "user": user,
        "ip": ip,
        "source": "EDR-Agent",
        "action": action_type,
        "detail": detail,
        "process_name": proc_name,
        "process_path": proc_path.replace("%USER%", user),
        "parent_process": parent,
        "stage": "Normal",
        "technique": "None",
        "severity": sev,
        "event_id": random.choice([1, 3, 5, 7, 10, 11, 13]),
    }


def main():
    parser = argparse.ArgumentParser(description="Synthetic EDR Log Generator")
    parser.add_argument("--count", type=int, default=10000, help="Number of events to generate")
    parser.add_argument("--output", choices=["file", "stdout", "console"], default="file", help="Output mode")
    parser.add_argument("--file", default="edr_events.json", help="Output file path")
    parser.add_argument("--rate", type=float, default=0, help="Rate limit in events/second (0 = unlimited)")
    args = parser.parse_args()

    # If relative filename given, resolve to current directory
    out_file = os.path.abspath(args.file)
    target_dir = os.path.dirname(out_file)
    if target_dir and not os.path.exists(target_dir):
        os.makedirs(target_dir, exist_ok=True)

    base_time = datetime(2026, 10, 31, 8, 0, 0, tzinfo=timezone.utc)
    current_time = base_time

    # Calculate interval per event
    time_step = timedelta(seconds=max(1, int(86400 / max(1, args.count))))

    # Plan attack injection points
    attack_indices = set()
    num_attacks = len(ATTACK_SCENARIOS)
    if args.count > num_attacks * 2:
        step_interval = max(1, args.count // (num_attacks + 1))
        for idx in range(num_attacks):
            attack_indices.add(step_interval * (idx + 1))

    handle = open(out_file, "w", encoding="utf-8") if args.output == "file" else sys.stdout
    attack_step_iter = iter(ATTACK_SCENARIOS)

    delay = 1.0 / args.rate if args.rate > 0 else 0
    t0 = time.time()

    try:
        for i in range(args.count):
            current_time += time_step
            user = random.choice(USERS)
            host = random.choice(HOSTS)
            ip = f"192.168.1.{random.randint(10, 150)}"

            if i in attack_indices:
                try:
                    att = next(attack_step_iter)
                    event = dict(att)
                    event["timestamp"] = current_time.strftime("%Y-%m-%dT%H:%M:%SZ")
                    event["time"] = event["timestamp"]
                    event["event_id"] = 1
                    event["process_name"] = "powershell.exe"
                except StopIteration:
                    event = generate_event(current_time, user, host, ip)
            else:
                event = generate_event(current_time, user, host, ip)

            line = json.dumps(event)
            handle.write(line + "\n")

            if delay > 0:
                time.sleep(delay)

            if (i + 1) % 2000 == 0 and args.output == "file":
                print(f"Generated {i + 1:,}/{args.count:,} events...", flush=True)

    finally:
        if args.output == "file":
            handle.close()

    elapsed = max(time.time() - t0, 0.001)
    if args.output == "file":
        size_mb = os.path.getsize(out_file) / (1024 * 1024)
        print(f"Successfully generated {args.count:,} EDR events ({size_mb:.2f} MB)")
        print(f"Saved to: {out_file}")
        print(f"Throughput: {args.count / elapsed:,.0f} events/second")


if __name__ == "__main__":
    main()
