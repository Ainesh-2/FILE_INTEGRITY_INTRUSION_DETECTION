import os
import subprocess
import threading
import time
import tkinter as tk

from baseline.base import create_baseline
from config.config_loader import load_config
from monitor.check import check_integrity, DASHBOARD_STATE
from monitor.dashboard import IDSDashboard


_SEVERITY = {
    "normal":               "LOW",
    "burst_activity":       "MEDIUM",
    "malware_like":         "HIGH",
    "destructive_activity": "HIGH",
    "ransomware_like":      "CRITICAL",
}


def _build_ui_state() -> dict:
    label = DASHBOARD_STATE.get("ai_label", "normal")
    issues_raw = DASHBOARD_STATE.get("baseline_issues", {})

    issue_lines: list[str] = []
    for filepath, state in list(issues_raw.items())[:5]:
        tag = "DELETED" if state == "DELETED" else "MODIFIED"
        issue_lines.append(f"[{tag}] {os.path.basename(filepath)}")
    overflow = len(issues_raw) - 5
    if overflow > 0:
        issue_lines.append(f"  … and {overflow} more")

    return {
        "severity":        _SEVERITY.get(label, "LOW"),
        "ai_type":         label,
        "confidence":      DASHBOARD_STATE.get("ai_confidence", 0.0),
        "modified":        DASHBOARD_STATE.get("modified", 0),
        "deleted":         DASHBOARD_STATE.get("deleted", 0),
        "new":             DASHBOARD_STATE.get("new", 0),
        "last_event":      DASHBOARD_STATE.get("last_event"),
        "baseline_issues": issue_lines,
    }


def _monitoring_loop(directories: list[str], interval: int) -> None:
    while True:
        for directory in directories:
            try:
                check_integrity(directory)
            except Exception as exc:
                print(f"[MONITOR ERROR] {exc}")
        time.sleep(interval)


def _push_to_gui(dashboard: IDSDashboard, root: tk.Tk) -> None:
    try:
        dashboard.update(_build_ui_state())
    except Exception:
        pass

    root.after(1000, _push_to_gui, dashboard, root)


def _run_create_baseline(directories: list[str]) -> None:
    print()
    for directory in directories:
        create_baseline(directory)
    print("\nBaseline created successfully.")


def _spawn_log_window() -> None:
    log_path = os.path.abspath(os.path.join("logs", "alerts.log"))
    ps_command = (
        f"$host.UI.RawUI.WindowTitle = 'IDS Live Logs'; "
        f"Get-Content '{log_path}' -Wait"
    )
    subprocess.Popen(
        ["powershell", "-NoExit", "-Command", ps_command],
        creationflags=subprocess.CREATE_NEW_CONSOLE,
    )


def _run_monitoring(directories: list[str], interval: int) -> None:
    print("\nStarting continuous monitoring...\n")

    _spawn_log_window()

    monitor = threading.Thread(
        target=_monitoring_loop,
        args=(directories, interval),
        daemon=True,
        name="IDS-Monitor",
    )
    monitor.start()

    root = tk.Tk()
    dashboard = IDSDashboard(root)

    root.after(1000, _push_to_gui, dashboard, root)
    root.mainloop()


def _print_menu() -> None:
    print()
    print("  ╔══════════════════════════════════╗")
    print("  ║      File Integrity IDS          ║")
    print("  ╠══════════════════════════════════╣")
    print("  ║  [1]  Create Baseline            ║")
    print("  ║  [2]  Continuous Monitoring      ║")
    print("  ╚══════════════════════════════════╝")
    print()


def _show_startup_menu(directories: list[str], interval: int) -> None:
    while True:
        _print_menu()
        choice = input("  Enter choice (1 or 2): ").strip()

        match choice:
            case "1":
                _run_create_baseline(directories)
                break
            case "2":
                _run_monitoring(directories, interval)
                break
            case _:
                print("\nInvalid choice!! Please enter 1 or 2.\n")


if __name__ == "__main__":
    config = load_config()
    directories = config.get("directories_to_monitor", ["."])
    interval = config.get("scan_interval_seconds", 10)

    _show_startup_menu(directories, interval)
