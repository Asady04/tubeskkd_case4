import json
import time
from base64 import b64decode
from Crypto.PublicKey import RSA, ElGamal
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import random as el_random
from paho.mqtt import client as mqtt_client

MQTT_BROKER = "broker.emqx.io"
MQTT_PORT = 1883
TOPIC_KEY_EXCHANGE = "tubeskkd/sharedkey"
TOPIC_PUBLISH = "tubeskkd/case4"
TOPIC_ACK = "tubeskkd/case4_ack"

# Generate RSA key
rsa_key = RSA.generate(2048)
rsa_pub = rsa_key.publickey().export_key().decode()

# Load ElGamal key from file
with open("elgamal_key.json", "r") as f:
    elgamal_data = json.load(f)

elgamal_key = ElGamal.construct((
    int(elgamal_data['p']),
    int(elgamal_data['g']),
    int(elgamal_data['y']),
    int(elgamal_data['x'])
))

elgamal_pub = {
    "p": str(elgamal_key.p),
    "g": str(elgamal_key.g),
    "y": str(elgamal_key.y)
}

def rsa_decrypt(ciphertext):
    cipher = PKCS1_OAEP.new(rsa_key)
    plaintext = cipher.decrypt(b64decode(ciphertext))
    return plaintext.decode(errors="ignore")

def elgamal_decrypt(ciphertext):
    c1, c2 = json.loads(ciphertext)
    c1, c2 = int(c1), int(c2)
    p, x = int(elgamal_key.p), int(elgamal_key.x)
    s = pow(c1, x, p)
    m = (c2 * pow(s, -1, p)) % p
    return m.to_bytes((m.bit_length() + 7) // 8, byteorder='big').decode(errors="ignore")

def connect_mqtt(client_id):
    client = mqtt_client.Client(client_id=client_id, protocol=mqtt_client.MQTTv311)
    client.connect(MQTT_BROKER, MQTT_PORT)
    return client

def send_public_keys(client):
    rsa_payload = json.dumps({"algorithm": "RSA", "key": rsa_pub})
    elgamal_payload = json.dumps({"algorithm": "ElGamal", "key": elgamal_pub})

    print("🔑 Sending RSA public key...")
    client.publish(TOPIC_KEY_EXCHANGE, rsa_payload)
    time.sleep(2)
    print("🔑 Sending ElGamal public key...")
    client.publish(TOPIC_KEY_EXCHANGE, elgamal_payload)

def on_message(client, userdata, msg):
    print(f"[📩] Message received on {msg.topic}: {msg.payload.decode()}")
    try:
        data = json.loads(msg.payload.decode())
    except json.JSONDecodeError:
        print("⚠️ Received non-JSON payload.")
        return

    if "cipher" not in data or "data" not in data:
        return  # skip ACKs or malformed

    uid = data.get("uid", "-")
    cipher = data["cipher"]
    payload = data["data"]

    try:
        if cipher == "RSA":
            decrypted = rsa_decrypt(payload)
        elif cipher == "ElGamal":
            decrypted = elgamal_decrypt(payload)
        else:
            print("⚠️ Unknown cipher type.")
            return

        print(f"[🔓] Decrypted ({cipher}): {decrypted}")
        client.publish(TOPIC_ACK, json.dumps({"uid": uid}))

    except Exception as e:
        print(f"[❌] Decryption error: {e}")

mqtt_sub = connect_mqtt("subscriber")
mqtt_sub.subscribe(TOPIC_PUBLISH)
mqtt_sub.on_message = on_message

send_public_keys(mqtt_sub)
print("🔐 Subscriber ready and listening...\n")
mqtt_sub.loop_forever()
