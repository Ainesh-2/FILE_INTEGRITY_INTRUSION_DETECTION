from baseline.base import create_baseline
from monitor.check import check_integrity
from config.config_loader import load_config
import subprocess
import time


if __name__ == "__main__":
    config = load_config()
    directory_to_monitor = config["directories_to_monitor"]

    print("Welcome to the File Integrity Monitor!")
    print("1. Create Baseline")
    print("2. Check Integrity")
    print("3. Continuous Monitoring")
    choice = input("Enter your choice: ")
    for directory in directory_to_monitor:
        print(f"Monitoring directory: {directory}")
        if choice == "1":
            create_baseline(directory)
        elif choice == "2":
            check_integrity(directory)
        elif choice == "3":
            subprocess.Popen(
                ["powershell", "-NoExit", "-Command",
                    "Get-Content logs\\alerts.log -Wait"],
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
            print("Starting continuous monitoring...")
            while True:
                try:
                    check_integrity(directory)
                    time.sleep(10)
                except KeyboardInterrupt:
                    print("Continuous monitoring stopped.")
                    break
        else:
            print("Invalid choice!!")
