# GuardianAV – Educational Antivirus (MVP)

![GuardianAV Screenshot](GuardianAV – Educational Antivirus (MVP) 17.8.2025. 20_45_09.png)

**GuardianAV** is a minimal, modern, and educational antivirus designed **strictly for learning and experimentation purposes**.  
It demonstrates practical file scanning, heuristic analysis, and GUI design using **Python and PyQt6**.

---

## ⭐ Features

- **Multi-tab GUI:** Dashboard, Scan, Quarantine, Logs, Settings  
- **Quick & Custom Scans:** Scan folders of your choice  
- **Heuristic Detection:** Detects suspicious files using extensions, entropy, and size  
- **Signature Matching:** SHA256 hash-based detection, including the EICAR test file  
- **Quarantine Management:** Move, restore, or delete suspicious files safely  
- **Real-time Logs:** Track all scan events and actions  
- **System Tray Integration:** Minimal background monitoring  

---

## 💻 Installation

1. Install **Python 3.10+**  
2. Install dependencies:

```bash
pip install PyQt6
Run the application:

bash
python GuardianAV.py
🚀 Usage
Open GuardianAV

Use Quick Scan or Custom Scan to select a folder

Monitor scanning progress in real-time

Quarantine, restore, or delete suspicious files

View detailed logs in the Logs tab

⚠️ Disclaimer
GuardianAV is strictly educational. It is NOT a replacement for a real antivirus.
Use it at your own risk. The developer is not responsible for any data loss, system issues, or other consequences that may occur.
Always test in a controlled environment or virtual machine.