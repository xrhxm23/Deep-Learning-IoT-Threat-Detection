from flask import Flask, jsonify
import pandas as pd
import os
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

LOG = "logs/detections.csv"

@app.route("/api/logs")
def logs():
    if not os.path.exists(LOG): return jsonify([])
    try:
        df = pd.read_csv(LOG)
        if df.empty: return jsonify([])
        return jsonify(df.tail(100).iloc[::-1].to_dict(orient="records"))
    except: return jsonify([])

@app.route("/api/stats")
def stats():
    if not os.path.exists(LOG):
        return jsonify({"total":0,"attacks":0,"normal":0})
    try:
        df = pd.read_csv(LOG)
        return jsonify({
            "total":   len(df),
            "attacks": int((df["result"]=="ATTACK").sum()),
            "normal":  int((df["result"]=="NORMAL").sum())
        })
    except: return jsonify({"total":0,"attacks":0,"normal":0})

if __name__=="__main__":
    print("[API] http://localhost:5000")
    app.run(port=5000,debug=False)