from baseline.base import create_baseline
from monitor.check import check_integrity
from config.config_loader import load_config

if __name__ == "__main__":
    config = load_config()
    directory_to_monitor = config["directories_to_monitor"]

    print("Welcome to the File Integrity Monitor!")
    print("1. Create Baseline")
    print("2. Check Integrity")
    choice = input("Enter your choice (1 or 2): ")
    for directory in directory_to_monitor:
        print(f"Monitoring directory: {directory}")
        if choice == "1":
            create_baseline(directory)
        elif choice == "2":
            check_integrity(directory)
        else:
            print("Invalid choice!!")
