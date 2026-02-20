from baseline.base import create_baseline
from monitor.check import check_integrity

if __name__ == "__main__":
    directory_to_monitor = "."

    print("Welcome to the File Integrity Monitor!")
    print("1. Create Baseline")
    print("2. Check Integrity")
    choice = input("Enter your choice (1 or 2): ")
    if choice == "1":
        create_baseline(directory_to_monitor)
    elif choice == "2":
        check_integrity(directory_to_monitor)
    else:
        print("Invalid choice!!")
