import time
import json
from Cryptodome.PublicKey import ElGamal
from Cryptodome.Random import get_random_bytes

ELGAMAL_KEY_PATH = "elgamal_key.json"

print("🔐 Generating ElGamal key... This might take a while.")
start = time.time()

key = ElGamal.generate(1024, get_random_bytes)

# Save each parameter as a decimal string
key_data = {
    "p": str(key.p),
    "g": str(key.g),
    "y": str(key.y),
    "x": str(key.x),
}

with open(ELGAMAL_KEY_PATH, "w") as f:
    json.dump(key_data, f)

print(f"✅ ElGamal key saved to '{ELGAMAL_KEY_PATH}' in {time.time() - start:.2f} seconds.")
