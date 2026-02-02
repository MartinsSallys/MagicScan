# MagicScan 🔮
Offline Malware Scanner for Windows systems using Linux Live environments.

## 🔥 Why MagicScan?
Malware can hide itself when the infected OS is running.
MagicScan performs detection **outside the compromised system**, reducing evasion by rootkits.

## 🧠 Features
- Offline scan (Linux Live)
- Read-only NTFS mount
- Hash-based detection (Abuse.ch)
- PE structure analysis
- JSON forensic reports

## 🚀 Usage

### 1. Boot Linux Live
Ubuntu / Kali / Rescue ISO.

### 2. Mount Windows partition (read-only)
```bash
sudo mount -o ro /dev/sda2 /mnt/windows
