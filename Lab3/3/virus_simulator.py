"""
virus_simulator.py
A safe, educational simulation of basic malware behaviors for learning and defense practice.
This tool does NOT modify, delete, or transmit any files or data.
"""
import os
import time
import random

# CONFIGURATION
TARGET_DIR = '.'  # Current directory
SIMULATED_SIGNATURE = 'dummy_virus_signature'


def scan_files(directory):
    """Simulate scanning files in a directory."""
    print(f"[SCAN] Scanning directory: {directory}")
    files = []
    for root, _, filenames in os.walk(directory):
        for fname in filenames:
            path = os.path.join(root, fname)
            files.append(path)
    print(f"[SCAN] Found {len(files)} files.")
    return files


def simulate_infection(files):
    """Simulate 'infecting' files (no real changes)."""
    infected = []
    for f in files:
        # Randomly decide to 'infect' a file
        if random.random() < 0.2:  # 20% chance
            print(f"[INFECT] Simulating infection of: {f}")
            infected.append(f)
            # No real file changes!
    print(f"[INFECT] Total infected (simulated): {len(infected)}")
    return infected


def simulate_detection(files):
    """Simulate detection of infected files."""
    detected = []
    for f in files:
        # Randomly detect some files as 'infected'
        if random.random() < 0.8:  # 80% detection rate
            print(f"[DETECT] Detected simulated infection in: {f}")
            detected.append(f)
    print(f"[DETECT] Total detected (simulated): {len(detected)}")
    return detected


def simulate_cleaning(files):
    """Simulate cleaning/removal of infections."""
    for f in files:
        print(f"[CLEAN] Simulated cleaning of: {f}")
    print(f"[CLEAN] Total cleaned (simulated): {len(files)}")


def main():
    print("\n=== Virus Simulation Tool (Safe & Educational) ===\n")
    files = scan_files(TARGET_DIR)
    infected = simulate_infection(files)
    detected = simulate_detection(infected)
    simulate_cleaning(detected)
    print("\n[INFO] Simulation complete. No files were harmed.\n")

if __name__ == "__main__":
    main()
