import pandas as pd

file_path = "cleaned_improved_cicids2017.csv" 

print("⏳ Scanning the 900MB dataset to create a smart balanced sample...")
print("This may take up to a minute because we are searching the whole file. Hang tight!")

# We will read the dataset in chunks to find both Benign and Attack traffic safely
benign_chunks = []
attack_chunks = []

# Loop through the massive file 100k rows at a time
for chunk in pd.read_csv(file_path, chunksize=100000):
    # Separate benign and attack traffic in this chunk
    benign_rows = chunk[chunk['Label'] == 'BENIGN']
    attack_rows = chunk[chunk['Label'] != 'BENIGN']
    
    # Save them
    if not benign_rows.empty:
        benign_chunks.append(benign_rows.sample(n=min(len(benign_rows), 10000), random_state=42))
    if not attack_rows.empty:
        attack_chunks.append(attack_rows)

print("📊 Scanning complete! Combining data...")

# Combine all the collected slices
all_attacks = pd.concat(attack_chunks)
all_benign = pd.concat(benign_chunks).sample(n=min(100000, len(all_attacks)*2), random_state=42)

# Create the final smart dataset (combining them together)
smart_sample = pd.concat([all_benign, all_attacks]).sample(frac=1, random_state=42) # frac=1 shuffles the data

print("\n🎯 NEW TRAFFIC DISTRIBUTION IN YOUR SAMPLE:")
print("-" * 45)
print(smart_sample['Label'].value_counts())
print("-" * 45)

# Overwrite the old sample file
smart_sample.to_csv("network_logs_sample.csv", index=False)
print("✅ Success! Your 'network_logs_sample.csv' is now perfectly balanced and ready for ML.")