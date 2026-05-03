import os
import time
import random

BASE_DIR = "simulation_workspace"
os.makedirs(BASE_DIR, exist_ok=True)


def simulate_normal():
    print("Simulating normal behaviour...")
    for i in range(random.randint(1, 4)):
        with open(f"{BASE_DIR}/normal_{i}.txt", "w") as f:
            f.write("This is a normal file.\n")
        time.sleep(0.5)


def simulate_burst():
    print("Simulating burst activity...")
    for i in range(60):
        with open(f"{BASE_DIR}/burst_{i}.txt", "w") as f:
            f.write("This is a burst file.\n")


def simulate_ransomware():
    print("Simulating ransomware behaviour...")
    files = []
    for i in range(50):
        filename = f"{BASE_DIR}/doc_{i}.txt"
        with open(filename, "w") as f:
            f.write("Important document.\n")
        files.append(filename)
    time.sleep(10)
    for file in files:
        new_name = file.replace(".txt", "encrypted_")
        os.rename(file, new_name)


def simulate_malware():
    print("Simulating malware dropper...")
    for i in range(3):
        with open(f"{BASE_DIR}/malware_{i}.exe", "w") as f:
            f.write("Fake Binary\n")
    with open(f"{BASE_DIR}/.hidden_config", "w") as f:
        f.write("Hidden configuration data\n")


def simulate_destructive():
    print("Simulating destructive activity...")
    temp_files = []
    for i in range(30):
        filename = f"{BASE_DIR}/temp_{i}.txt"
        with open(filename, "w") as f:
            f.write("Temporary file.\n")
        temp_files.append(filename)
    print("files created... waiting for IDS scan")
    time.sleep(10)
    for file in temp_files:
        os.remove(file)
    print("Temporary files deleted.")


if __name__ == "__main__":
    print("Select activity to simulate:")
    print("1. Normal")
    print("2. Burst")
    print("3. Ransomware")
    print("4. Malware")
    print("5. Destructive")
    choice = input("Enter your choice (1-5): ")
    if choice == "1":
        simulate_normal()
    elif choice == "2":
        simulate_burst()
    elif choice == "3":
        simulate_ransomware()
    elif choice == "4":
        simulate_malware()
    elif choice == "5":
        simulate_destructive()
    else:
        print("Invalid choice.")
    print("Simulation complete.")
