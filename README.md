# 🛡️ File Integrity & Intrusion Detection System

> A Python-based security system that detects unauthorized file changes using cryptographic hashing.

---

## 🎯 Objective

Detect suspicious file activity and possible intrusions by comparing current file states with a trusted baseline snapshot.

The system identifies:

🔹 Modified files  
🔹 Deleted files  
🔹 Newly created files  
🔹 Baseline tampering attempts  

---

# 🔑 Key Features

---

## 1️⃣ File Integrity Monitoring

Ensures that important files remain unchanged.

Uses **SHA-256 cryptographic hashing** to detect differences between:

### Detects:

📝 File modification  
❌ File deletion  
➕ New file creation  

---

## 2️⃣ Baseline Snapshot

Creates a trusted snapshot of all monitored files.

Each file stores:
🔹Hash Value
🔹File Size
🔹Last Modified

---

## 3️⃣ Baseline Tamper Detection

Attackers may try to modify the baseline itself.

To prevent this:

The system stores a hash of the baseline file.

baseline.json → hashed → stored separately

During verification:

new hash == stored hash ?

If not:

🚨 Baseline tampering detected
Integrity check aborted

---

## 4️⃣ Configurable Monitoring

System behaviour is controlled using:

config/config.json

Allows user to define:

📂 directories to monitor
🚫 directories to ignore
📄 file types to ignore
⚠️ severity levels

---

## 5️⃣ Severity Based Logging
Alerts are classified as:

| Severity    |          Meaning            |
|-------------|-----------------------------|
| 🟢  LOW    | new file detected           |
| 🟡  HIGH   | file modified or deleted    |
| 🔴CRITICAL | baseline tampering detected |
| 🔵  INFO   | summary information         |

---
