import pickle
import queue
import threading
import numpy as np
from datetime import datetime
from collections import defaultdict
from scapy.all import AsyncSniffer, IP, TCP, UDP

# ─────────────────────────────────────────
# FEATURE ORDER — must match training exactly
# ─────────────────────────────────────────
FEATURE_NAMES = ['pkts', 'bytes', 'dur', 'mean', 'stddev',
                 'rate', 'srate', 'drate', 'sum', 'min', 'max']

# ─────────────────────────────────────────
# LOAD SCALER AND MODEL
# ─────────────────────────────────────────
print("Loading scaler and model...")

try:
    with open("models/scaler.pkl", "rb") as f:
        scaler = pickle.load(f)
    print("[OK] Scaler loaded")
except FileNotFoundError:
    print("[ERROR] scaler.pkl not found. Run train.py first.")
    exit()

try:
    import tensorflow as tf
    import os
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # suppress TF warnings
    model = tf.keras.models.load_model("models/model.h5")
    print("[OK] Model loaded")
except Exception as e:
    print(f"[ERROR] Could not load model: {e}")
    exit()

# ─────────────────────────────────────────
# THREAD-SAFE QUEUE (GUI reads from this)
# ─────────────────────────────────────────
prediction_queue = queue.Queue(maxsize=100)

# ─────────────────────────────────────────
# FLOW TRACKER
# Groups packets by (src_ip, dst_ip) to build flow features
# ─────────────────────────────────────────
flow_table = defaultdict(lambda: {
    'pkts': 0,
    'bytes': [],
    'start_time': None,
    'last_time': None,
    'src_ip': ''
})
flow_lock = threading.Lock()
FLOW_TIMEOUT = 2  # seconds — classify flow after 2s of inactivity

def get_flow_features(flow):
    """Build feature vector from accumulated flow data."""
    pkt_sizes = flow['bytes']
    pkts      = float(flow['pkts'])
    total     = float(sum(pkt_sizes))
    dur       = max((flow['last_time'] - flow['start_time']), 0.001)
    mean      = total / pkts if pkts > 0 else 0.0
    stddev    = float(np.std(pkt_sizes)) if len(pkt_sizes) > 1 else 0.0
    rate      = pkts / dur
    srate     = rate / 2
    drate     = rate / 2
    pkt_sum   = total
    pkt_min   = float(min(pkt_sizes))
    pkt_max   = float(max(pkt_sizes))

    return np.array([[pkts, total, dur, mean, stddev,
                      rate, srate, drate, pkt_sum,
                      pkt_min, pkt_max]], dtype=np.float32)

# ─────────────────────────────────────────
# PREDICT AND LOG
# ─────────────────────────────────────────
def predict_flow(flow_key, flow):
    """Scale features and run ANN prediction."""
    try:
        features = get_flow_features(flow)
        scaled   = scaler.transform(features)
        prob     = model.predict(scaled, verbose=0)[0][0]
        label    = int(prob > 0.5)
        src_ip   = flow['src_ip']

        result = {
            "timestamp":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip":     src_ip,
            "label":      label,
            "confidence": round(float(prob), 4),
            "result":     "ATTACK" if label == 1 else "NORMAL"
        }

        if not prediction_queue.full():
            prediction_queue.put(result)

        tag = "[!!ATTACK!!]" if label == 1 else "[  NORMAL  ]"
        print(f"{tag} {result['timestamp']} | IP: {src_ip} "
              f"| pkts: {int(flow['pkts'])} "
              f"| confidence: {result['confidence']}")

        # Log attacks to CSV
        if label == 1:
            with open("logs/detections.csv", "a") as log:
                log.write(f"{result['timestamp']},{src_ip},ATTACK,{result['confidence']}\n")

    except Exception as e:
        print(f"[WARN] Prediction error: {e}")

# ─────────────────────────────────────────
# PACKET HANDLER
# ─────────────────────────────────────────
def handle_packet(packet):
    if IP not in packet:
        return

    src_ip  = packet[IP].src
    dst_ip  = packet[IP].dst
    pkt_len = len(packet)
    now     = datetime.now().timestamp()
    key     = (src_ip, dst_ip)

    with flow_lock:
        flow = flow_table[key]
        if flow['start_time'] is None:
            flow['start_time'] = now
            flow['src_ip']     = src_ip
        flow['pkts']      += 1
        flow['bytes'].append(pkt_len)
        flow['last_time']  = now

# ─────────────────────────────────────────
# FLOW TIMEOUT CHECKER — runs every 2 seconds
# Classifies flows that haven't had new packets
# ─────────────────────────────────────────
def flow_checker():
    while True:
        threading.Event().wait(FLOW_TIMEOUT)
        now = datetime.now().timestamp()
        with flow_lock:
            timed_out = [
                k for k, v in flow_table.items()
                if v['last_time'] and (now - v['last_time']) >= FLOW_TIMEOUT
            ]
            for key in timed_out:
                flow = flow_table.pop(key)
                if flow['pkts'] >= 2:  # only classify flows with 2+ packets
                    threading.Thread(
                        target=predict_flow,
                        args=(key, flow),
                        daemon=True
                    ).start()

# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────
if __name__ == "__main__":

    # Write CSV header
    import os
    os.makedirs("logs", exist_ok=True)
    
    with open("logs/detections.csv", "w") as log:
        log.write("timestamp,src_ip,result,confidence\n")

    # Start flow checker thread
    checker_thread = threading.Thread(target=flow_checker, daemon=True)
    checker_thread.start()

    # Start sniffer
    try:
        print("\n[INFO] Starting packet sniffer...")
        print("[INFO] Classifying flows — results appear every 2 seconds.")
        print("[INFO] Press Ctrl+C to stop.\n")

        sniffer = AsyncSniffer(
            filter="ip",
            prn=handle_packet,
            store=False
        )
        sniffer.start()

        while True:
            threading.Event().wait(1)

    except PermissionError:
        print("[ERROR] Permission denied — run as Administrator.")
    except KeyboardInterrupt:
        print("\n[INFO] Stopping sniffer...")
        sniffer.stop()
        print("[INFO] Detections saved to logs/detections.csv")
        print("[INFO] Done.")