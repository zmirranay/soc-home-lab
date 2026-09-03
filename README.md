# SOC Home Lab

A hands-on, defensive security home lab built to practise the core skills of a SOC (Security Operations Centre) analyst: detecting attacks in Windows logs, log analysis, and triage.

The lab is an isolated VirtualBox environment with a Windows victim machine and a Kali attacker machine, fully instrumented with logging (Sysmon, PowerShell script block logging, and Windows audit policy). Each project runs an attack on purpose, then hunts for the evidence it left behind in the logs.

## Projects

| # | Project | Core skill |
|---|---------|-----------|
| 1 | [Lab Build](01-lab-build/) | Building and documenting a monitored environment |
| 2 | Baseline Normal Activity | Knowing what normal looks like |
| 3 | Detect an Nmap Scan | Spotting reconnaissance |
| 4 | Detect Malicious PowerShell | Reading what a script did |
| 5 | Detect a Failed-Logon Attack | Spotting brute force |
| 6 | Build a Detection Rule | Automating detection (SIEM) |

Each project is written up in **Scenario / Findings / Escalation** format.

## Lab Design

| Machine | Role | IP address | OS |
|---|---|---|---|
| Windows10-Victim | Victim (monitored) | 192.168.10.10 | Windows 10 |
| kali-linux | Attacker | 192.168.10.20 | Kali Linux |

Both VMs sit on an isolated VirtualBox Internal Network so that any malicious activity stays contained.

## Tools

- **VirtualBox** — virtualisation
- **Sysmon** (Microsoft Sysinternals) with the SwiftOnSecurity config — detailed process and network logging
- **Windows Event Viewer** — reading the logs
- **PowerShell script block logging** and **Windows audit policy** — additional log sources
- **Splunk Free** (planned) — SIEM for automated detection
