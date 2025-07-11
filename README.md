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
