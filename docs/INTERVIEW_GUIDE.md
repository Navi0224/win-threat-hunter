# Interview guide: win-threat-hunter

This guide is for you, the author. Read it until you can explain every part
of the project without notes. Interviewers for SOC and detection-engineering
roles care less about how much code you wrote. They care whether you
understand **why** each piece exists and what its weaknesses are.

---

## 1. The one-sentence pitch

> "It's a Python CLI that reads Windows event logs, runs YAML detection rules
> mapped to MITRE ATT&CK over them, correlates events like brute force followed
> by a successful logon, and produces a prioritised report with evidence and a
> response action for each finding."

## 2. Walkthrough of each module

Follow the data: **files -> Events -> Findings -> reports**.

### `models.py`: the shared vocabulary

- `Event` is one Windows event after normalisation: `event_id`, `timestamp`
  (always UTC), `channel`, `provider`, `computer`, a `data` dict of the named
  fields (TargetUserName, IpAddress, CommandLine...), and `source` (file and
  line number).
- `Rule`, `Detection`, `Condition`, `Threshold`, `Sequence` describe a rule.
- `Finding` is an alert: the rule, the evidence events, the group key (e.g.
  `IpAddress=203.0.113.45`) and notes.

**Why designed this way:** every other module talks in these types. The
parsers don't know about rules, and the engine doesn't know about file
formats. That separation means adding a new input format (say, CSV) touches
only one file.

**Why `source` matters:** an analyst must be able to go back to the original
record. "Trust but verify" applies to your own tools.

### `parsers.py`: getting data in

- `.evtx`: uses `python-evtx` to read each record's XML. `event_from_xml` pulls
  out `System` (EventID, time, channel, computer, provider) and the named
  `<Data>` fields. Some events, such as 1102 "log cleared", put their fields
  in `<UserData>` instead, so those are flattened too.
- `.jsonl` / `.json`: `event_from_dict` accepts several key spellings (`EventID`
  or `Id`, `Channel` or `LogName`...) because different export methods name
  things differently.
- `parse_timestamp` copes with Windows quirks: 7-digit fractional seconds,
  `Z` suffix, and the `/Date(1700000000000)/` format from Windows PowerShell 5.1.
  Everything is converted to **UTC**.

**Design decisions you should be able to defend:**
- *Bad records are skipped and counted, not fatal.* One corrupt line must not
  stop you seeing the attack in the other million lines. The report shows how
  many were skipped, so it's not silent.
- *UTC everywhere.* Correlation compares times. If one log is in UTC+8
  (Malaysia) and another in UTC, a 10-minute window becomes meaningless.
- *Events are sorted by time after loading*, because correlation assumes order.
- *Files read with `utf-8-sig`*, because Windows PowerShell 5.1 adds a
  byte-order mark that would otherwise break the first line.

### `rules.py`: loading and validating rules

- Uses `yaml.safe_load`, never `yaml.load`. Plain `load` can create arbitrary
  Python objects from YAML tags, which is a code-execution risk if someone
  hands you a malicious rule file.
- Strict validation: unknown operator, missing `response`, a technique ID not
  shaped like `T1234` or `T1234.567`, duplicate rule IDs, a bad regex. All of
  these raise a `RuleError` with the file name.
- Values are lower-cased and regexes compiled **once, at load time**, not once
  per event.

**Why strict:** in a SOC, the most dangerous rule is one that *looks* deployed
but silently never fires because of a typo. Failing loudly is safer.

### `engine.py`: the detection logic

Three layers:

1. `matches_condition`: one test on one event. A condition can list several
   fields (OR), several values (OR), and can be negated. Comparisons are
   case-insensitive, because Windows is case-insensitive and attackers use
   `PoWeRsHeLl.ExE` to dodge case-sensitive matching.
2. `matches_detection`: checks the EventID first (cheap and rules out most
   events), then the optional channel, then the conditions with `all` (AND) or
   `any` (OR).
3. Rule types:
   - **single**: every match is a finding.
   - **threshold** (`run_threshold`): groups matching events by a key (e.g.
     source IP) and uses a sliding time window. When the window holds `count`
     events (or `count` *distinct* values of a field) it raises a finding. Then
     it **keeps adding** further events from the same burst to that finding
     until the group has been quiet for a whole window. Result: one alert per
     attack, not dozens.
   - **sequence** (`run_sequence`): for each event that matches the *last*
     step (e.g. a 4624 success), look back `window_seconds` in the same group
     and check the earlier steps happened *in order* with their minimum counts.
     Evidence that has been used for one finding is not reused for another.

### `enrich.py`: helping the analyst

Finds `-EncodedCommand` (and its short forms `-e`, `-ec`, `-enc`...) and
decodes the Base64. PowerShell encodes **UTF-16LE**, not UTF-8. That's a
detail interviewers like, because decoding as UTF-8 gives text full of null
bytes.

### `report.py`: getting results out

- Console: `rich` table, coloured by severity. If `rich` isn't installed it
  falls back to plain text.
- JSON: complete, machine-readable, keeps every evidence event (for a SIEM or
  a ticket).
- Markdown / HTML: human-readable, with ATT&CK links, response actions, known
  false positives, and up to 10 evidence rows. When there are more, it shows
  the **first and last** events, so the final "success" event in a brute force
  is never hidden.
- **Security:** log content is attacker-controlled. Someone can create a user
  called `<script>...</script>`. The HTML report escapes everything with
  `html.escape`, and the console escapes `rich` markup. A test checks this.

### `cli.py`: the front door

`wth hunt` and `wth list-rules`. Exit codes are 0 for OK and 2 for an error.
`--fail-on high` returns 1 when serious findings exist, so the tool can be
used in scripts.

### Tests (`tests/`)

- `test_parsers.py`: timestamp formats, BOM, broken lines, JSON arrays, EVTX XML.
- `test_rule_loader.py`: bad rules are rejected with useful messages.
- `test_engine.py`: operators, negation, threshold edge cases (below count,
  outside window, separate groups, long burst = one finding, distinct counting)
  and sequence edge cases (wrong order, outside window, different IP).
- `test_rules_on_samples.py`: **every rule against the sample data with an
  exact expected count.** This is "detection-as-code": change a rule and
  break it, and CI tells you.
- `test_report.py`, `test_cli.py`, `test_enrich.py`.

---

## 3. Key concepts

### Windows Event IDs used in this project

| ID | Log | Meaning | Why an attacker cares |
|---|---|---|---|
| 4624 | Security | Successful logon | Proves access worked. **LogonType** matters: 2 = at the keyboard, 3 = network (SMB), 10 = RDP |
| 4625 | Security | Failed logon | Password guessing / spraying |
| 4720 | Security | User account created | Backdoor account for persistence |
| 4728 / 4732 / 4756 | Security | Member added to global / local / universal group | Privilege escalation (e.g. into Administrators) |
| 1102 | Security | Security audit log cleared | Covering tracks |
| 104 | System | Another event log cleared | Covering tracks |
| 4688 | Security | Process created (with command line if enabled) | See what ran |
| 4698 | Security | Scheduled task created | Persistence |
| 7045 | System | Service installed | Persistence / running as SYSTEM (PsExec does this) |
| 4104 | PowerShell Operational | Script block logged | Shows the *decoded* script that ran, even if it was obfuscated on the command line |
| Sysmon 1 | Sysmon Operational | Process creation with parent, hashes, command line | Richer than 4688: parent-child relationships |

### MITRE ATT&CK

A public knowledge base of real attacker behaviour, organised as **tactics**
(the *why*: Credential Access, Persistence, Defense Evasion...) and
**techniques** (the *how*: T1110 Brute Force, T1053.005 Scheduled Task...).
Sub-techniques have a dot: T1110.003 is Password Spraying.

Why map rules to it:
1. It gives the whole team one shared language.
2. You can see **coverage gaps** ("we have nothing for Lateral Movement").
3. Each technique page lists detections and mitigations, which saves research time.

### False positives (FP) and false negatives (FN)

- FP = alert, but benign (an admin creating a user). Too many FPs and analysts
  start ignoring alerts (*alert fatigue*), which is how real attacks get missed.
- FN = attack, but no alert. Usually caused by missing logs or evasion.
- This project reduces FPs with **thresholds**, **exclusions** (`negate`),
  **context** (e.g. *suspicious* service path) and **severity tiers** (WTH-008
  low vs WTH-009 high for the same Event ID). Each rule documents its known
  FPs, so the analyst knows what to check first.

### Correlation windows

One failed logon means nothing. Ten from one IP in five minutes is a pattern.
A window turns noise into signal. Choosing the size is a trade-off:
- Too **short**: a slow attacker (one guess per minute) stays under the
  threshold. This is called "low and slow".
- Too **long**: unrelated normal failures add up and cause FPs. It also uses
  more memory in a streaming system.
- **Group-by** matters as much as the window. Grouping failures by *source IP*
  catches brute force. Counting *distinct usernames* per IP catches spraying,
  which deliberately stays under per-account lockout limits.

---

## 4. Ten likely interview questions, with model answers

**1. Walk me through what happens when I run `wth hunt`.**
> The CLI loads and validates all YAML rules first, so a broken rule fails
> before any work is done. Then the parsers read each input file into a common
> `Event` object, with timestamps converted to UTC and events sorted by time.
> The engine runs each rule: single-event rules check each event, threshold
> rules group events and use a sliding window, and sequence rules look back
> from the final step. Findings get enriched (for example, encoded PowerShell
> is decoded), sorted by severity, and written to the console and optionally
> to JSON, Markdown and HTML.

**2. How does your brute-force detection work, and how could an attacker evade it?**
> WTH-001 counts 4625 events per source IP in a 5-minute sliding window and
> fires at 10. Local console failures with no IP are excluded so a user typing
> badly at their own keyboard isn't flagged. Evasion: go slower than 10 per 5
> minutes, spread attempts across many IPs (a botnet), or spray one password
> across many users. That last one is why I have WTH-003, which counts
> *distinct usernames* per IP. A real SOC would also correlate across hosts
> and use longer baselines.

**3. Why is "brute force followed by success" critical but brute force alone only medium?**
> Failed attempts are attempts. The internet is full of them. A success from
> the same IP straight after many failures means the attacker probably *has
> valid credentials now*. That changes the response from "block the IP" to
> "assume the account is compromised": reset the password, kill sessions, and
> review what that account did next.

**4. How do you handle false positives?**
> Four ways in this project. Thresholds, so a single typo doesn't alert.
> Exclusions with `negate`. Context, so a new service is low severity but a
> new service whose path runs `cmd.exe` or lives in a temp folder is high.
> And documentation: every rule lists its known false positives. In a real
> team I'd add allow-lists for known-good software and track each rule's FP
> rate so noisy rules get tuned or retired.

**5. Why YAML rules instead of hard-coding detections in Python?**
> It separates *what* to detect from *how* to run it. Analysts who don't write
> Python can read and review rules. Rules can be version-controlled and peer
> reviewed like code ("detection-as-code"), and the engine stays small and
> tested. It's the same idea as Sigma, the industry-standard rule format. A
> natural next step is a Sigma importer.

**6. What's in Event ID 4104, and why is it valuable?**
> It's PowerShell Script Block Logging. It records the script that actually
> ran, *after* PowerShell has decoded it. So even if the command line only
> shows a Base64 blob, 4104 shows the real code, like the `IEX ... DownloadString`
> in my sample data. It must be enabled by policy, and attackers sometimes try
> to downgrade to PowerShell v2, which doesn't log it.

**7. Why does an Office application starting PowerShell matter?**
> Word and Excel almost never need to start a shell. When they do, it's
> usually a malicious macro from a phishing attachment, which is ATT&CK
> T1204.002 User Execution: Malicious File. It's a high-signal, low-noise
> detection. Its weakness is that it matches on the image path, so a renamed
> `powershell.exe` would get past it. Sysmon's `OriginalFileName` field would
> fix that.

**8. Your tool shows "No findings". Is the machine clean?**
> Not necessarily. Absence of evidence is not evidence of absence. First check
> coverage: is auditing enabled for logons, account management and process
> creation? Is command-line logging on? Is Sysmon installed? Were the logs
> cleared or did they roll over? The report shows how many events were
> parsed, which is a first sanity check.

**9. What security issues did you think about in the tool itself?**
> Three main ones. Log data is attacker-controlled, so I escape it in the HTML
> report to prevent XSS against the analyst, and I escape `rich` markup in
> the console. I load YAML with `safe_load` so a rule file can't execute code.
> And the parser never crashes on malformed input: it skips and counts bad
> records, so an attacker can't hide activity by inserting one broken record.
> I also made sure real logs aren't accidentally committed, via `.gitignore`.

**10. If you had another month, what would you add?**
> A Sigma rule importer, so I could use thousands of community rules. Allow-lists
> to cut false positives. Rules for credential dumping, such as Sysmon Event 10
> for LSASS access. A streaming parser for big files. And output in a SIEM
> schema like Elastic Common Schema. I'd also test it against a lab with real
> attack simulations, for example Atomic Red Team, to measure which ATT&CK
> techniques it actually catches.

**Bonus quick-fire answers**
- *LogonType 3 vs 10?* 3 = network logon (SMB, mapped drive), 10 = RDP.
- *What is a download cradle?* A one-liner that downloads and runs code in
  memory, e.g. `IEX (New-Object Net.WebClient).DownloadString(url)`.
- *Why UTF-16LE for -EncodedCommand?* Windows strings are UTF-16LE internally,
  and PowerShell expects the Base64 of that.
- *Threshold vs sequence?* Threshold = "how many". Sequence = "in what order".

---

## 5. How to demo in 2 minutes

Prepare beforehand: venv activated, terminal font readable, a terminal window
at least 150 characters wide, and the HTML report already generated in a
browser tab.

1. **(15 s) The problem.** "Windows logs thousands of events. I built a tool
   that finds the handful that show an attack, explains them, and says what to
   do next."
2. **(15 s) Show a rule.** Open `rules/002_bruteforce_then_success.yml`. "Rules
   are YAML, mapped to ATT&CK. This one is a sequence: five failures then a
   success from the same IP within 10 minutes."
3. **(30 s) Run it.**
   ```
   wth hunt samples/sample_events.jsonl -v --html out/report.html
   ```
   Point at row 1, the CRITICAL brute-force-then-success, then the decoded
   PowerShell note: "it decoded the attacker's Base64 automatically, and you
   can see the download URL."
4. **(30 s) The HTML report.** Click one finding: ATT&CK link, timeline,
   evidence rows with file:line, recommended response.
5. **(15 s) False positives.** `wth hunt samples/benign_only.jsonl`. "Normal
   activity gives only a low and a medium triage item. Nothing high."
6. **(15 s) Tests.** `python -m pytest -q`. "Every rule has a test that pins
   how many times it fires on known data. Detection-as-code."

Finish with one limitation and one next step. It shows you're honest: "It
only sees what Windows logged, so a missed audit policy means missed attacks.
Next I'd add a Sigma importer."

## 6. Things to be honest about if asked

- The sample data is synthetic. You wrote the attack story; it is not a real breach.
- The rules are simplified versions of real-world detections. Production
  versions need allow-lists and tuning per environment.
- `.evtx` reading was checked by hand against a few public sample files. The
  PowerShell export script's conversion logic was tested with mock records,
  so run it on your own laptop before the interview and be ready to say what
  you saw.
