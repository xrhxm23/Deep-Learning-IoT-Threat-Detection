import pickle, threading, numpy as np
from datetime import datetime
from collections import defaultdict
from scapy.all import AsyncSniffer, IP, TCP, UDP
import os, tensorflow as tf

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

with open("models/scaler.pkl","rb") as f:
    scaler = pickle.load(f)
print(f"[OK] Scaler — {scaler.n_features_in_} features")
model = tf.keras.models.load_model("models/model.h5")
print("[OK] Model loaded\n")

flow_table = defaultdict(lambda:{
    'proto':0,'sizes':[],'src_port':0,'dst_port':0,
    'flags':0,'last_time':None,'start_time':None,'src_ip':''
})
flow_lock = threading.Lock()

def predict(flow):
    sizes = flow['sizes']
    if len(sizes) < 2: return
    iat = (flow['last_time'] - flow['start_time']) / max(len(sizes)-1,1)
    X = np.array([[float(flow['proto']),float(np.mean(sizes)),
                   float(flow['src_port']),float(flow['dst_port']),
                   float(flow['flags']),float(iat)]],dtype=np.float32)
    X = np.nan_to_num(X)
    prob  = float(model.predict(scaler.transform(X),verbose=0)[0][0])
    label = "ATTACK" if prob > 0.5 else "NORMAL"
    tag   = "[!!ATTACK!!]" if label=="ATTACK" else "[  NORMAL  ]"
    ts    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{tag} {ts} | IP: {flow['src_ip']} | pkts: {len(sizes)} | conf: {round(prob,4)}")
    os.makedirs("logs",exist_ok=True)
    with open("logs/detections.csv","a") as f:
        f.write(f"{ts},{flow['src_ip']},{label},{round(prob,4)}\n")

def handle_packet(pkt):
    if IP not in pkt: return
    now = datetime.now().timestamp()
    key = (pkt[IP].src, pkt[IP].dst)
    sp=dp=flags=0
    if TCP in pkt: sp,dp,flags=pkt[TCP].sport,pkt[TCP].dport,int(pkt[TCP].flags)
    elif UDP in pkt: sp,dp=pkt[UDP].sport,pkt[UDP].dport
    with flow_lock:
        fl=flow_table[key]
        if fl['start_time'] is None:
            fl.update({'start_time':now,'src_ip':pkt[IP].src,
                      'proto':pkt[IP].proto,'src_port':sp,'dst_port':dp,'flags':flags})
        fl['sizes'].append(len(pkt))
        fl['last_time']=now

def checker():
    while True:
        threading.Event().wait(2)
        now=datetime.now().timestamp()
        with flow_lock:
            done=[k for k,v in flow_table.items()
                  if v['last_time'] and now-v['last_time']>=2]
            for k in done:
                fl=flow_table.pop(k)
                threading.Thread(target=predict,args=(fl,),daemon=True).start()

if __name__=="__main__":
    os.makedirs("logs",exist_ok=True)
    with open("logs/detections.csv","w") as f:
        f.write("timestamp,src_ip,result,confidence\n")
    threading.Thread(target=checker,daemon=True).start()
    try:
        print("[INFO] Sniffer running — press Ctrl+C to stop\n")
        sniffer=AsyncSniffer(filter="ip",prn=handle_packet,store=False)
        sniffer.start()
        while True: threading.Event().wait(1)
    except PermissionError: print("[ERROR] Run as Administrator")
    except KeyboardInterrupt:
        sniffer.stop()
        print("\n[INFO] Done.")