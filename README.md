# 🛡️ File Integrity & Intrusion Detection System

> A Python-based security system that detects unauthorized file changes using cryptographic hashing, AI-powered classification, and a live Tkinter dashboard.

---

## 🎯 Objective

Detect suspicious file activity and possible intrusions by comparing current file states with a trusted baseline snapshot.

The system identifies:

🔹 Modified files  
🔹 Deleted files  
🔹 Newly created files  
🔹 Baseline tampering attempts  
🔹 AI-classified intrusion patterns  
🔹 File resolutions (previously flagged files returning to a clean state)  

---

## 🧠 System Design

The IDS follows a layered architecture:

- **Baseline Layer** → Ensures long-term file integrity against the original trusted snapshot
- **Snapshot Layer** → Detects real-time changes between consecutive scan cycles
- **AI Layer** → Classifies behaviour using extracted file-activity features

This separation of concerns improves accuracy, scalability, and maintainability.

---

## 🚀 Getting Started

Run the program from the project root:

```bash
python -m app.main
```

A CLI menu will appear:

```
  ╔══════════════════════════════════╗
  ║      File Integrity IDS          ║
  ╠══════════════════════════════════╣
  ║  [1]  Create Baseline            ║
  ║  [2]  Continuous Monitoring      ║
  ╚══════════════════════════════════╝

  Enter choice (1 or 2):
```

🔹 **1 — Create Baseline** → Scans all monitored directories and saves a trusted snapshot  
🔹 **2 — Continuous Monitoring** → Starts the background scan loop and opens the live dashboard  

---

# 🔑 Key Features

---

## 1️⃣ File Integrity Monitoring

Ensures that important files remain unchanged.

Uses **SHA-256 cryptographic hashing** to detect differences between the current state and the saved baseline.

### Detects:

📝 File modification  
❌ File deletion  
➕ New file creation  
✅ File resolution — when a previously flagged file returns to its baseline state  
🔄 File re-appearance — when a deleted file reappears with mismatched content  

### Two-Layer Checking:

| Layer | What it compares | Purpose |
|---|---|---|
| **Baseline Layer** | Current files vs. `base.json` | Long-term integrity vs. the original snapshot |
| **Snapshot Layer** | Current files vs. previous scan | Detects changes *between* cycles in real-time |

---

## 2️⃣ Baseline Snapshot

Creates a trusted snapshot of all monitored files.

Each file entry stores:  
🔹 Hash Value (SHA-256)  
🔹 File Size  
🔹 Last Modified timestamp  

Saved to `baseline/base.json`.

---

## 3️⃣ Baseline Tamper Detection

Attackers may try to modify the baseline itself.

To prevent this:

The system stores a hash of the baseline file.

```
baseline/base.json → hashed → stored in baseline/base.hash
```

During verification:

```
new hash == stored hash ?
```

If not:

🚨 Baseline tampering detected  
Integrity check aborted  

---

## 4️⃣ AI-Powered Intrusion Classification

Every scan cycle is analysed by a trained **Random Forest** model.

### Features fed to the model:

| Feature | Description |
|---|---|
| `modified_count` | Number of modified files this cycle |
| `deleted_count` | Number of deleted files this cycle |
| `new_count` | Number of new files this cycle |
| `executable_count` | Count of new `.exe`, `.bat`, `.ps1`, `.sh` files |
| `unique_extensions` | Variety of file types among new files |
| `unique_dirs` | Number of distinct directories affected |

### Classification labels:

| Label                  | Severity   | Description                               |
|------------------------|------------|-------------------------------------------|
| `normal`               | 🟢 LOW     | No suspicious activity                    |
| `burst_activity`       | 🟡 MEDIUM  | Unusually high number of new files        |
| `malware_like`         | 🔴 HIGH    | Pattern consistent with malware           |
| `destructive_activity` | 🔴 HIGH    | Mass deletions detected                   |
| `ransomware_like`      | 🚨 CRITICAL| Encrypt-then-delete file pattern          |

### Configurable AI Thresholds (`config/config.json`):

| Threshold | Default | Meaning |
|---|---|---|
| `burst_new_count` | 40 | New file count to trigger `burst_activity` |
| `destructive_deleted` | 40 | Deleted file count to trigger `destructive_activity` |
| `quiet_total` | 2 | Total changes at or below which forces `normal` |

### Alert Deduplication:

The AI layer compares each result to the previous alert. If the **label and features are identical**, no duplicate log entry is written — reducing noise in the log file.

The model is stored in `ai/intrusion_model.pkl` and was trained on `ai/training_data.csv`.

---

## 5️⃣ Live Tkinter Dashboard

Continuous Monitoring mode opens a real-time GUI dashboard showing:

🖥️ Current threat severity  
🤖 AI classification label and confidence  
📊 Counts of modified, deleted, and new files  
🗂️ List of affected baseline files  
🕒 Last detected event  

The dashboard updates every second via a background daemon thread that writes to a shared state dict (`DASHBOARD_STATE`).

## 6️⃣ Daily Summary Logging

At the end of each day (or when the program exits), an automatic summary is written to the log:

```
Daily Summary [YYYY-MM-DD]: Modified=X, Deleted=Y, New=Z
```

This uses Python's `atexit` hook and a date-rollover check on every scan cycle so no data is lost even if the process is stopped mid-day.

---

## 7️⃣ Configurable Monitoring

System behaviour is controlled using:

```
config/config.json
```

Allows the user to define:

📂 Directories to monitor  
🚫 Directories to ignore  
📄 File types to ignore  
⏱️ Scan interval (seconds)  
⚠️ Severity levels  

---

## 8️⃣ Severity-Based Logging

Alerts are classified as:

| Severity      | Config Key          | Default Meaning                              |
|---------------|---------------------|----------------------------------------------|
| 🟢  LOW       | `NEW`               | New file detected                            |
| 🟡  MEDIUM    | *(AI-assigned)*     | Burst of file activity                       |
| 🔴  HIGH      | `MODIFIED`, `DELETED` | File modified or deleted                   |
| 🚨  CRITICAL  | `BASELINE_TAMPERED`, `LOG_TAMPERED` | Baseline or log file tampered |
| 🔵  INFO      | `RESOLVED`          | Flagged file returned to clean state / daily summary |

All severity levels are fully customisable in `config/config.json` under `severity_levels`.

---

## 🗂️ Project Structure

```
File_Integrity_Intrusion_Detection/
│
├── app/
│   └── main.py              # Entry point — CLI menu + dashboard launcher
│
├── monitor/
│   ├── check.py             # Core integrity check logic + DASHBOARD_STATE
│   └── dashboard.py         # Tkinter live dashboard widget
│
├── baseline/
│   ├── base.py              # Baseline creation & tamper detection
│   ├── base.json            # Saved baseline snapshot
│   └── base.hash            # Hash of baseline file
│
├── ai/
│   ├── predictor.py         # AI inference using trained model
│   ├── train_model.py       # Model training script
│   ├── gen_training_data.py # Training data generator
│   ├── intrusion_model.pkl  # Trained Random Forest model
│   └── training_data.csv    # Training dataset
│
├── hashing/
│   ├── hasher.py            # SHA-256 file hashing
│   └── scanner.py           # Directory file scanner
│
├── config/
│   ├── config.json          # User configuration
│   └── config_loader.py     # Config loader utility
│
├── logs/
│   └── alerts.log           # Alert log output
│
└── tests/                   # Unit tests
```

---

## 🔮 Future Improvements

🔹 Event-driven monitoring (OS-level file system hooks)  
🔹 Web-based dashboard  
🔹 Automated response system (quarantine / block)  
🔹 Improved ML model trained on real-world datasets  
🔹 Baseline versioning and rollback  

---
