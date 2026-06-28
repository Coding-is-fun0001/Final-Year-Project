# Final-Year-Project

# Ransomware Early Detection and Response System

## 1. Project Overview

This project is a behavior-based ransomware early detection and response system developed for Final Year Project (FYP). The system monitors file system activities in real time and detects suspicious behaviors commonly associated with ransomware attacks, such as rapid file modifications, suspicious file extensions, abnormal entropy changes, and unauthorized access to honeypot files.

Once suspicious behavior is detected, the system generates alerts, collects forensic evidence, and attempts to suspend or terminate the malicious process to reduce damage.

---

## 2. Key Features

* Real-time file system monitoring
* Entropy-based ransomware detection
* Frequency-based anomaly detection
* Honeypot file protection
* Suspicious extension detection
* Hardware anomaly monitoring (CPU and memory usage)
* Process suspension and termination
* Quarantine of suspicious executable files
* Forensic evidence collection and reporting
* GUI alert dashboard

---

## 3. System Requirements

### Operating System

* Windows 10 / Windows 11 (Recommended)
* Linux (Partially supported)

### Python Version

* Python 3.10 or above recommended
* Minimum: Python 3.9

### Required Python Libraries

* psutil
* watchdog
* tkinter (usually preinstalled on Windows)

Install dependencies:

```bash
pip install psutil watchdog
```

---

## 4. Project Structure

project/
│
├── FYP_v12.py
├── ransomware_config.json
├── quarantine/
├── forensic/
├── logs/
└── monitored_folder/

---

## 5. Configuration

System settings can be configured in:

ransomware_config.json

Important parameters:

* suspicious_exts
* monitored_exts
* entropy_delta_threshold
* threshold_1s
* threshold_1h
* whitelist_paths

Example monitored file extensions:

* .doc
* .docx
* .xls
* .xlsx
* .ppt
* .pptx
* .pdf
* .txt
* .csv
* .sql
* .db

---

## 6. Execution Guide

### Step 1: Prepare monitored folder

Create a folder for monitoring:

Example:
C:\test_monitor

Add sample files such as:

* report.docx
* notes.txt
* database.db

---

### Step 2: Run as Administrator (Important)

The program should be executed with Administrator privileges to ensure accurate process identification and process termination capability.

Without Administrator privileges:

* PID detection accuracy decreases
* Some processes cannot be terminated
* Access to open file handles may be limited

Recommended:
Right Click → Run as Administrator

---

### Step 3: Execute the system

Run:

```bash
python FYP_v12.py
```

The system will:

* Build baseline
* Create honeypot files
* Start real-time monitoring
* Start hardware anomaly monitoring
* Launch GUI dashboard

---

## 7. Detection Mechanisms

The system uses multiple detection layers:

### 1. Suspicious Extension Detection

Detects ransomware-related file extensions:

* .encrypted
* .locked
* .crypt
* .crypto
* .ransom

---

### 2. Entropy-Based Detection

The system compares file entropy changes.

Detection rule:

Entropy Difference = Current Entropy - Baseline Entropy

If entropy increase exceeds threshold, an alert is triggered.

---

### 3. Frequency-Based Detection

Detects abnormal file activity:

* Rapid file modifications
* Mass file creation
* Bulk encryption behavior

---

### 4. Honeypot Detection

Decoy files are placed in monitored folders.

Any access, modification, or deletion of honeypot files is treated as highly suspicious.

---

## 8. Testing Procedure

To simulate ransomware:

1. Run the detection system
2. Execute ransomware simulator
3. Modify multiple monitored files rapidly
4. Rename files to suspicious extensions
5. Observe alert generation

Expected results:

* Alert popup appears
* Suspicious process identified
* Process terminated or suspended
* Forensic report generated

---

## 9. Limitations

* Administrator privileges are recommended for best detection performance.
* Process identification is not guaranteed in all cases.
* Some sophisticated ransomware may evade detection.
* The system is behavior-based and detects attacks after suspicious behavior begins.
* Detection accuracy depends on configured thresholds and monitored file types.

---

## 10. Conclusion

This project demonstrates a practical behavior-based ransomware detection and response solution that combines entropy analysis, frequency monitoring, honeypot protection, and process control to reduce ransomware impact in real-time.
