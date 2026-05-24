import pandas as pd

# Trim the huge network file
print("✂️ Trimming network dataset...")
df_net = pd.read_csv("cleaned_improved_cicids2017.csv", nrows=2000)
df_net.to_csv("cleaned_improved_cicids2017.csv", index=False)

print("✅ Trimming complete! Files are now perfectly optimized for GitHub.")