import json
import time
import random
import string
import threading
import statistics
from base64 import b64encode
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Cryptodome.Random import random as el_random
from paho.mqtt import client as mqtt_client
import matplotlib.pyplot as plt

MQTT_BROKER = "broker.emqx.io"
MQTT_PORT = 1883
TOPIC_KEY_EXCHANGE = "tubeskkd/sharedkey"
TOPIC_MAIN = "tubeskkd/case4"
TOPIC_ACK = "tubeskkd/case4_ack"

PLAINTEXT_SIZES = [50, 100, 150]
SAMPLES = 100

received_keys = {}
message_timings = {}
lock = threading.Lock()

def generate_random_plaintext(size):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=size)).encode()

def rsa_encrypt_factory(public_key):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return lambda msg: b64encode(cipher.encrypt(msg)).decode()

def elgamal_encrypt_factory(public_key_data):
    p, g, y = int(public_key_data['p']), int(public_key_data['g']), int(public_key_data['y'])
    def encrypt(msg):
        m = int.from_bytes(msg, byteorder='big')
        k = el_random.StrongRandom().randint(1, p - 2)
        c1 = pow(g, k, p)
        s = pow(y, k, p)
        c2 = (m * s) % p
        return json.dumps((c1, c2))
    return encrypt

def connect_mqtt(client_id):
    client = mqtt_client.Client(client_id=client_id, protocol=mqtt_client.MQTTv311)
    client.connect(MQTT_BROKER, MQTT_PORT)
    return client

def on_key_message(client, userdata, msg):
    data = json.loads(msg.payload.decode())
    with lock:
        received_keys[data['algorithm']] = data['key']
    print(f"[✅] Stored {data['algorithm']} key.")

def on_ack_message(client, userdata, msg):
    try:
        data = json.loads(msg.payload.decode())
        uid = data['uid']
        with lock:
            if uid in message_timings:
                message_timings[uid]['recv_time'] = time.time()
    except Exception as e:
        print(f"[ACK error] {e}")

mqtt_pub = connect_mqtt("publisher")
mqtt_pub.loop_start()
mqtt_pub.on_message = on_key_message
mqtt_pub.subscribe(TOPIC_KEY_EXCHANGE)
mqtt_pub.message_callback_add(TOPIC_ACK, on_ack_message)
mqtt_pub.subscribe(TOPIC_ACK)

print("📡 Waiting for public keys from subscriber...")
while len(received_keys) < 2:
    time.sleep(1)

print("🔓 All public keys received:")
for algo in received_keys:
    print(f"  - {algo} ✅")

rsa_encrypt = rsa_encrypt_factory(received_keys['RSA'])
elgamal_encrypt = elgamal_encrypt_factory(received_keys['ElGamal'])

def benchmark(cipher_name, encrypt_func, timeout_per_algo):
    results = {}
    timeout_val = timeout_per_algo.get(cipher_name, 3)

    print(f"\n🚀 Starting benchmark for {cipher_name} encryption")
    for size in PLAINTEXT_SIZES:
        comp_times = []
        comm_times = []
        print(f"\n📦 Testing {cipher_name} with plaintext size: {size} bytes")

        for i in range(SAMPLES):
            uid = f"{cipher_name}_{size}_{i}_{random.randint(1, 999999)}"
            plaintext = generate_random_plaintext(size)
            print(f"🔄 [{cipher_name} {size} bytes] Sample {i+1}/{SAMPLES} - Generating and encrypting...")

            t1 = time.time()
            ciphertext = encrypt_func(plaintext)
            t2 = time.time()
            comp_delay = t2 - t1
            comp_times.append(comp_delay)
            print(f"✅ Encrypted in {comp_delay:.6f}s")

            payload = json.dumps({"uid": uid, "cipher": cipher_name, "data": ciphertext})
            with lock:
                message_timings[uid] = {"send_time": time.time()}
            mqtt_pub.publish(TOPIC_MAIN, payload)
            print(f"📤 Published to broker with UID: {uid}")

            timeout = time.time() + timeout_val
            while time.time() < timeout:
                with lock:
                    if uid in message_timings and 'recv_time' in message_timings[uid]:
                        comm_delay = message_timings[uid]['recv_time'] - message_timings[uid]['send_time']
                        comm_times.append(comm_delay)
                        print(f"📬 ACK received. Comm delay: {comm_delay:.6f}s\n")
                        del message_timings[uid]
                        break
                time.sleep(0.005)
            else:
                print(f"⚠️ Timeout: No ACK for UID: {uid}\n")

        results[size] = (comp_times, comm_times)
    return results

# Run benchmarks
timeout_settings = {
    "RSA": 2,
    "ElGamal": 4
}

rsa_results = benchmark("RSA", rsa_encrypt, timeout_settings)
elgamal_results = benchmark("ElGamal", elgamal_encrypt, timeout_settings)


# Plotting
def plot_bar(title, rsa_vals, elgamal_vals, ylabel):
    x = PLAINTEXT_SIZES
    width = 4
    plt.figure(figsize=(8, 5))
    plt.bar([p - width/2 for p in x], rsa_vals, width, label='RSA')
    plt.bar([p + width/2 for p in x], elgamal_vals, width, label='ElGamal')
    plt.xlabel("Message Size (bytes)")
    plt.ylabel(ylabel)
    plt.title(title)
    plt.xticks(x)
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()

# Per-sample plot
for algo, result in [("RSA", rsa_results), ("ElGamal", elgamal_results)]:
    for size in PLAINTEXT_SIZES:
        comp, comm = result[size]
        plt.figure(figsize=(10, 5))
        min_len = min(len(comp), len(comm))
        plt.plot(range(1, min_len + 1), comp[:min_len], label="Computational Delay")
        plt.plot(range(1, min_len + 1), comm[:min_len], label="Communication Delay")
        plt.title(f"{algo} - {size} bytes")
        plt.xlabel("Sample Index")
        plt.ylabel("Delay (s)")
        plt.legend()
        plt.grid(True)
        plt.tight_layout()
        plt.show()

# Aggregate bar plots
rsa_avg_comp = [statistics.mean(rsa_results[size][0]) for size in PLAINTEXT_SIZES]
elgamal_avg_comp = [statistics.mean(elgamal_results[size][0]) for size in PLAINTEXT_SIZES]
rsa_avg_comm = [statistics.mean(rsa_results[size][1]) for size in PLAINTEXT_SIZES]
elgamal_avg_comm = [statistics.mean(elgamal_results[size][1]) for size in PLAINTEXT_SIZES]

plot_bar("Average Computational Delay", rsa_avg_comp, elgamal_avg_comp, "Time (s)")
plot_bar("Average Communication Delay", rsa_avg_comm, elgamal_avg_comm, "Time (s)")
