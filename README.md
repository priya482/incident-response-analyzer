
# Incident Response Analyzer
**Author:** Priyanshi Dhokiya  
**Language:** Python 3.11  
**Framework:** MITRE ATT&CK  

## Overview
A Python-based security tool that analyzes log files for indicators of compromise, maps findings to the MITRE ATT&CK framework, and automatically generates a prioritized incident response report.

Built to simulate real SOC analyst workflows for threat detection and incident documentation.

## What It Detects
- Brute force attacks (T1110.001)
- After-hours suspicious logins (T1078)
- Sensitive file access (T1083)
- New admin account creation (T1136.001)
- Privilege escalation (T1068)
- Connections from known malicious IPs

## How It Works
1. Reads security log file
2. Analyzes each event for attack patterns
3. Maps findings to MITRE ATT&CK techniques
4. Checks IPs against known malicious list
5. Generates timestamped incident report with recommendations

## Sample Output
- 11 findings detected across 6 attack categories
- Critical findings escalated with immediate action required
- Full report saved as timestamped .txt file

## Skills Demonstrated
- Python scripting and automation
- Security log analysis
- MITRE ATT&CK framework
- Incident response workflows
- Threat detection and documentation
