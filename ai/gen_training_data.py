import pandas as pd
import numpy as np


def generate_samples(label, n, mod_range, del_range, new_range, exe_range, ext_range, dir_range):
    return pd.DataFrame({
        "modified": np.random.randint(*mod_range, n),
        "deleted": np.random.randint(*del_range, n),
        "new": np.random.randint(*new_range, n),
        "exe_created": np.random.randint(*exe_range, n),
        "ext_changed": np.random.randint(*ext_range, n),
        "unique_dirs": np.random.randint(*dir_range, n),
        "label": label
    })


df_normal = generate_samples(
    "normal", 600, (0, 5), (0, 2), (0, 3), (0, 1), (0, 2), (1, 3))
df_ransom = generate_samples(
    "ransomware_like", 250, (40, 150), (0, 3), (0, 5), (0, 1), (30, 120), (5, 30))
df_malware = generate_samples(
    "malware_like", 250, (2, 12), (0, 2), (3, 15), (1, 5), (0, 3), (2, 6))
df_burst = generate_samples(
    "burst_activity", 200, (15, 60), (0, 5), (5, 20), (0, 1), (5, 15), (4, 10))
df_delete = generate_samples(
    "destructive_activity", 200, (0, 10), (15, 70), (0, 5), (0, 1), (0, 3), (2, 10))

df = pd.concat([df_normal, df_ransom, df_malware, df_burst, df_delete])

df = df.sample(frac=1)

df.to_csv("ai/training_data.csv", index=False)

print("Training data generated and saved to ai/training_data.csv")
