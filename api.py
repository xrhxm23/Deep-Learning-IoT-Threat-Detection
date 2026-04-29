from flask import Flask, jsonify, request
import pandas as pd
import os
import json
from datetime import datetime
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

LOG = "logs/detections.csv"
DEVICES_FILE = "devices.json"

def load_devices():
    if not os.path.exists(DEVICES_FILE):
        return []
    with open(DEVICES_FILE, "r") as f:
        return json.load(f).get("devices", [])

def save_devices(devices):
    with open(DEVICES_FILE, "w") as f:
        json.dump({"devices": devices}, f, indent=2)

@app.route("/api/logs")
def logs():
    if not os.path.exists(LOG):
        return jsonify([])
    try:
        df = pd.read_csv(LOG)
        if df.empty:
            return jsonify([])
        return jsonify(df.tail(100).iloc[::-1].to_dict(orient="records"))
    except:
        return jsonify([])

@app.route("/api/stats")
def stats():
    if not os.path.exists(LOG):
        return jsonify({"total": 0, "attacks": 0, "normal": 0})
    try:
        df = pd.read_csv(LOG)
        return jsonify({
            "total":   len(df),
            "attacks": int((df["result"] == "ATTACK").sum()),
            "normal":  int((df["result"] == "NORMAL").sum())
        })
    except:
        return jsonify({"total": 0, "attacks": 0, "normal": 0})

@app.route("/api/devices", methods=["GET"])
def get_devices():
    return jsonify(load_devices())

@app.route("/api/devices", methods=["POST"])
def add_device():
    data = request.get_json()
    devices = load_devices()
    new_device = {
        "id":       len(devices) + 1,
        "name":     data.get("name", "Unknown Device"),
        "ip":       data.get("ip", ""),
        "type":     data.get("type", "Unknown"),
        "location": data.get("location", ""),
        "status":   "Monitoring",
        "added":    datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    devices.append(new_device)
    save_devices(devices)
    return jsonify(new_device)

@app.route("/api/devices/<int:device_id>", methods=["DELETE"])
def delete_device(device_id):
    devices = load_devices()
    devices = [d for d in devices if d["id"] != device_id]
    save_devices(devices)
    return jsonify({"success": True})

@app.route("/api/devices/stats")
def device_stats():
    devices = load_devices()
    if not os.path.exists(LOG):
        return jsonify([])
    try:
        df = pd.read_csv(LOG)
        stats = []
        for device in devices:
            device_df = df[df["src_ip"] == device["ip"]]
            stats.append({
                "id":       device["id"],
                "name":     device["name"],
                "ip":       device["ip"],
                "type":     device["type"],
                "location": device["location"],
                "total":    len(device_df),
                "attacks":  int((device_df["result"] == "ATTACK").sum()),
                "normal":   int((device_df["result"] == "NORMAL").sum()),
                "status":   "THREAT" if len(device_df) > 0 and (device_df["result"] == "ATTACK").sum() > 0 else "SECURE"
            })
        return jsonify(stats)
    except:
        return jsonify([])

if __name__ == "__main__":
    print("[API] Running at http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)