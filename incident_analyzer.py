import re
import os
from datetime import datetime

# ============================================================
# INCIDENT RESPONSE ANALYZER v2.0
# Analyst: Priyanshi Dhokiya
# Description: Analyzes security logs for indicators of 
# compromise and maps findings to MITRE ATT&CK framework
# ============================================================

# Create sample log file if it doesn't exist
def create_sample_logs():
    logs = """2025-03-01 08:15:23 FAILED LOGIN user=admin ip=192.168.1.105
2025-03-01 08:15:24 FAILED LOGIN user=admin ip=192.168.1.105
2025-03-01 08:15:25 FAILED LOGIN user=admin ip=192.168.1.105
2025-03-01 08:15:26 FAILED LOGIN user=admin ip=192.168.1.105
2025-03-01 08:15:27 FAILED LOGIN user=admin ip=192.168.1.105
2025-03-01 08:15:28 SUCCESS LOGIN user=admin ip=192.168.1.105
2025-03-01 09:30:00 SUCCESS LOGIN user=john ip=10.0.0.5
2025-03-01 02:45:00 SUCCESS LOGIN user=sarah ip=185.220.101.45
2025-03-01 03:10:00 FILE ACCESS user=sarah ip=185.220.101.45 file=payroll.xlsx
2025-03-01 03:11:00 FILE ACCESS user=sarah ip=185.220.101.45 file=passwords.txt
2025-03-01 03:12:00 FILE ACCESS user=sarah ip=185.220.101.45 file=employee_data.xlsx
2025-03-01 10:00:00 USER CREATED user=backdoor_admin ip=192.168.1.105
2025-03-01 10:01:00 PRIVILEGE ESCALATION user=backdoor_admin ip=192.168.1.105"""
    
    with open("security.log", "w") as f:
        f.write(logs)
    print("[*] Sample log file created: security.log")

# MITRE ATT&CK mapping
MITRE_MAPPING = {
    "brute_force": {
        "technique": "T1110.001 - Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "severity": "CRITICAL"
    },
    "after_hours": {
        "technique": "T1078 - Valid Accounts",
        "tactic": "Initial Access",
        "severity": "HIGH"
    },
    "sensitive_files": {
        "technique": "T1083 - File and Directory Discovery",
        "tactic": "Discovery",
        "severity": "HIGH"
    },
    "new_admin": {
        "technique": "T1136.001 - Create Account: Local Account",
        "tactic": "Persistence",
        "severity": "CRITICAL"
    },
    "privilege_escalation": {
        "technique": "T1068 - Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "severity": "CRITICAL"
    }
}

# Known malicious IPs
MALICIOUS_IPS = ["185.220.101.45", "45.33.32.156", "198.20.69.74"]

# Sensitive file keywords
SENSITIVE_FILES = ["payroll", "password", "employee", "salary", "confidential", "secret"]

def analyze_logs(filename):
    findings = []
    failed_logins = {}
    
    with open(filename, "r") as f:
        lines = f.readlines()
    
    print(f"\n[*] Loaded {len(lines)} log entries from {filename}")
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        # Extract common fields
        ip_match = re.search(r'ip=(\S+)', line)
        user_match = re.search(r'user=(\S+)', line)
        time_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
        
        ip = ip_match.group(1) if ip_match else "unknown"
        user = user_match.group(1) if user_match else "unknown"
        timestamp = time_match.group(1) if time_match else "unknown"
        hour = int(timestamp.split(" ")[1].split(":")[0]) if timestamp != "unknown" else 12

        # Check 1 - Failed logins (Brute Force)
        if "FAILED LOGIN" in line:
            failed_logins[ip] = failed_logins.get(ip, 0) + 1
            if failed_logins[ip] == 5:
                findings.append({
                    "type": "brute_force",
                    "timestamp": timestamp,
                    "user": user,
                    "ip": ip,
                    "detail": f"5+ failed login attempts detected"
                })

        # Check 2 - After hours access
        if "SUCCESS LOGIN" in line and (hour < 6 or hour > 22):
            findings.append({
                "type": "after_hours",
                "timestamp": timestamp,
                "user": user,
                "ip": ip,
                "detail": f"Login at {hour}:00 outside business hours"
            })

        # Check 3 - Sensitive file access
        if "FILE ACCESS" in line:
            file_match = re.search(r'file=(\S+)', line)
            if file_match:
                filename_accessed = file_match.group(1).lower()
                for keyword in SENSITIVE_FILES:
                    if keyword in filename_accessed:
                        findings.append({
                            "type": "sensitive_files",
                            "timestamp": timestamp,
                            "user": user,
                            "ip": ip,
                            "detail": f"Accessed sensitive file: {file_match.group(1)}"
                        })
                        break

        # Check 4 - New admin account created
        if "USER CREATED" in line:
            findings.append({
                "type": "new_admin",
                "timestamp": timestamp,
                "user": user,
                "ip": ip,
                "detail": f"New user account created: {user}"
            })

        # Check 5 - Privilege escalation
        if "PRIVILEGE ESCALATION" in line:
            findings.append({
                "type": "privilege_escalation",
                "timestamp": timestamp,
                "user": user,
                "ip": ip,
                "detail": f"Privilege escalation detected for user: {user}"
            })

        # Check 6 - Known malicious IP
        if ip in MALICIOUS_IPS:
            findings.append({
                "type": "after_hours",
                "timestamp": timestamp,
                "user": user,
                "ip": ip,
                "detail": f"Connection from known malicious IP: {ip}"
            })

    return findings

def generate_report(findings):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"incident_report_{timestamp}.txt"
    
    critical = [f for f in findings if MITRE_MAPPING[f['type']]['severity'] == 'CRITICAL']
    high = [f for f in findings if MITRE_MAPPING[f['type']]['severity'] == 'HIGH']
    
    report = []
    report.append("=" * 65)
    report.append("         INCIDENT RESPONSE ANALYSIS REPORT")
    report.append("=" * 65)
    report.append(f"Analyst:       Priyanshi Dhokiya")
    report.append(f"Generated:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"Log Source:    security.log")
    report.append(f"Total Findings: {len(findings)}")
    report.append(f"Critical:      {len(critical)}")
    report.append(f"High:          {len(high)}")
    report.append("=" * 65)
    
    report.append("\nDETAILED FINDINGS:")
    report.append("-" * 65)
    
    for i, finding in enumerate(findings, 1):
        mitre = MITRE_MAPPING[finding['type']]
        report.append(f"\nFinding #{i}")
        report.append(f"Severity:      {mitre['severity']}")
        report.append(f"Timestamp:     {finding['timestamp']}")
        report.append(f"User:          {finding['user']}")
        report.append(f"IP Address:    {finding['ip']}")
        report.append(f"Detail:        {finding['detail']}")
        report.append(f"MITRE Tactic:  {mitre['tactic']}")
        report.append(f"MITRE Tech:    {mitre['technique']}")
        
        if mitre['severity'] == 'CRITICAL':
            report.append(f"Action:        IMMEDIATE ESCALATION REQUIRED")
        else:
            report.append(f"Action:        Investigate and monitor")
    
    report.append("\n" + "=" * 65)
    report.append("RECOMMENDATIONS:")
    report.append("-" * 65)
    report.append("1. Block IP 192.168.1.105 immediately at firewall level")
    report.append("2. Reset admin account credentials and enable MFA")
    report.append("3. Investigate sarah account for full compromise scope")
    report.append("4. Disable backdoor_admin account immediately")
    report.append("5. Review all privileged account activity for past 30 days")
    report.append("=" * 65)
    report.append("END OF REPORT")
    report.append("=" * 65)
    
    report_text = "\n".join(report)
    print(report_text)
    
    with open(report_file, "w") as f:
        f.write(report_text)
    
    print(f"\n[*] Report saved to: {report_file}")

# Main execution
print("=" * 65)
print("    INCIDENT RESPONSE ANALYZER v2.0")
print("    Priyanshi Dhokiya | Cybersecurity Portfolio")
print("=" * 65)

create_sample_logs()
findings = analyze_logs("security.log")
print(f"\n[*] Analysis complete. {len(findings)} findings detected.")
generate_report(findings)