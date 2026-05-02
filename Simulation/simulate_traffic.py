import joblib
import numpy as np
import pandas as pd
import time
import random
from colorama import init, Fore, Style

# Initialize colors for terminal output
init(autoreset=True)

print(f"{Fore.CYAN}==================================================")
print(f"{Fore.CYAN}   IOT INTRUSION DETECTION SYSTEM - SIMULATION    ")
print(f"{Fore.CYAN}==================================================\n")

# Load the trained RF model and Scaler
print("Loading Random Forest Model and Scaler...")
try:
    rf_model = joblib.load('ids_rf_model.pkl')
    scaler = joblib.load('scaler.pkl')
    print(f"{Fore.GREEN}Model loaded successfully!{Style.RESET_ALL}\n")
except Exception as e:
    print(f"{Fore.RED}Error loading files: {e}")
    print("Make sure ids_rf_model.pkl and scaler.pkl are in the same folder as this script.")
    exit()

# Attack Categories Mapping
categories = {
    0: 'Benign',
    1: 'Botnet',
    2: 'BruteForce',
    3: 'DDoS',
    4: 'DoS'
}

# Number of features the model expects (46 features from your dataset)
n_features = 46

def generate_synthetic_traffic(is_attack=False):
    """Generates synthetic network traffic features."""
    if not is_attack:
        # Benign traffic characteristics (low rate, low packet size, etc.)
        traffic = np.random.uniform(low=0, high=0.5, size=n_features)
    else:
        # Malicious traffic characteristics (high rate, huge packet counts, etc.)
        traffic = np.random.uniform(low=0.8, high=5.0, size=n_features)
    return traffic

print("Starting live traffic monitoring...\n")

# Run simulation
for i in range(1, 21):  # Simulate 20 real-time packets
    time.sleep(1.5)  # Pause to simulate real-time arrival
    
    # Randomly decide if this incoming packet is an attack or benign
    is_attack = random.random() > 0.6  # 40% chance of being an attack
    
    # Generate the packet
    raw_packet = generate_synthetic_traffic(is_attack=is_attack)
    
    # The model was trained on scaled data, so we must scale this packet!
    # scaler expects a 2D array, so we reshape
    packet_scaled = scaler.transform(raw_packet.reshape(1, -1))
    
    # Predict!
    prediction = rf_model.predict(packet_scaled)[0]
    category = categories[prediction]
    
    # Display Result
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    ip_source = f"192.168.1.{random.randint(10, 50)}"
    ip_dest = "192.168.1.1" # Gateway / IDS IP
    
    print(f"[{timestamp}] Packet {i:02d} | Src: {ip_source} -> Dst: {ip_dest}")
    if category == 'Benign':
        print(f"   => {Fore.GREEN}Status: {category} (Permitted){Style.RESET_ALL}\n")
    else:
        print(f"   => {Fore.RED}ALERT! Status: {category} Detected (Blocked){Style.RESET_ALL}\n")

print(f"{Fore.CYAN}Simulation Complete.")
