# 🛡️ YARA Rules Collection

## 👩‍💻 Author: Supriya Reddy

This project contains a set of custom YARA rules designed to detect different types of malware patterns such as ransomware, PowerShell payloads, and suspicious binaries. These rules are created and tested using Kali Linux.
Yara-Rules-Collection/
├── rules/ # YARA rule files (.yar)
├── samples/ # Test files used to validate rules
└── README.md # Project documentation
### 📁 Folders
- `rules/` – Contains `.yar` files with detection rules
- `samples/` – Test files to validate rules
---

## 📜 YARA Rules Included

- **ransomware_rule.yar**  
  Detects common ransomware message strings such as `"Your files have been encrypted"`.

- **powershell_base64.yar** 
  Detects Base64-encoded PowerShell commands often used in malware delivery.

- **keylogger_rule.yar**  
  Detects common strings or APIs used by keyloggers like `GetAsyncKeyState`.

---

## 🧪 How to Test YARA Rules

### ✅ 1. Install YARA (if not already)
```bash
sudo apt update
sudo apt install yara
### 🔧 How to Use
1. Install YARA on Kali Linux: `sudo apt install yara`
2. Run a rule on a file:
.YARA (Yet Another Recursive Acronym) is a tool used in cybersecurity to identify and classify malwares based on textual or binary patterns (signatures). It is widely used by malware researchers and threat hunters.
.Save rule as .yar or .yara

.Where are YARA Rules Used?
  In tools like VirusTotal, MalwareBazaar, Velociraptor, Falcon Sandbox, Kali Linux
  Inside SIEM and EDR systems for threat detection
  On memory dumps or disk images during malware analysis

##Basic Structure of a YARA Rule
rule RuleName
{
    meta:
        key = "value"

    strings:
        $string1 = "text to find"
        $string2 = { 6A 40 68 00 30 00 00 }   // Hex pattern
        $string3 = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/  // Regex

    condition:
        any of them
}

***Sections of a YARA Rule
1.rule
Starts the rule and names it.
Example: rule Ransomware_Detect

2.meta: (Optional)
Adds metadata like author, description, date, etc.
Helps with documentation.
meta:
    author = "Supriya"
    description = "Detects ransomware strings"
    date = "2025-07-10"

3.strings:
The most important section.
Defines the patterns to look for.
Each string is given a name (like $a, $b, or $password) and a pattern to match.
Types of strings:
Text strings: $a = "This program cannot be run"
Hex strings: $b = { E8 ?? ?? ?? ?? 68 }hex strings to find specific byte patterns in files, like executable headers, shellcode, or encoded malware.
Regex strings: $c = /malware[0-9]{1,3}/ You want to find dynamic patterns, like:Email addresses,IP addresses,URLs,Variable names
   In YARA, regex must be between /slashes/.

4.condition:
Tells YARA when to trigger a match.
Examples:
any of them — if any string matches
all of them — if all strings match
#a > 5 — more than 5 occurrences of string $a
filesize < 1MB — only if file is under 1MB

