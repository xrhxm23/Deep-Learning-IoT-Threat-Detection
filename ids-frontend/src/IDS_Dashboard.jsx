import { useState, useEffect, useRef } from "react";

export default function IDSDashboard() {
  const [logs, setLogs] = useState([]);
  const [running, setRunning] = useState(false);
  const [filter, setFilter] = useState("ALL");
  const [attackCount, setAttackCount] = useState(0);
  const [normalCount, setNormalCount] = useState(0);
  const [trendData, setTrendData] = useState(Array(30).fill(0));
  const [glitch, setGlitch] = useState(false);
  const [gridCells, setGridCells] = useState([]);
  const [activeTab, setActiveTab] = useState("dashboard");
  const [deviceStats, setDeviceStats] = useState([]);
  const [showAddDevice, setShowAddDevice] = useState(false);
  const [newDevice, setNewDevice] = useState({ name:"", ip:"", type:"Smart Camera", location:"" });
  const intervalRef = useRef(null);
  const GRID_COLS = 40, GRID_ROWS = 12;

  useEffect(() => {
    setGridCells(Array.from({ length: GRID_COLS * GRID_ROWS }, (_, i) => ({
      id: i, active: Math.random() < 0.15, attack: false,
    })));
    fetchDevices();
    const di = setInterval(fetchDevices, 5000);
    return () => clearInterval(di);
  }, []);

  const flashGlitch = () => { setGlitch(true); setTimeout(() => setGlitch(false), 300); };

  const fetchDevices = async () => {
    try {
      const res = await fetch("http://localhost:5000/api/devices/stats");
      setDeviceStats(await res.json());
    } catch(e) {}
  };

  const addDevice = async () => {
    if (!newDevice.name || !newDevice.ip) return;
    await fetch("http://localhost:5000/api/devices", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(newDevice)
    });
    setNewDevice({ name:"", ip:"", type:"Smart Camera", location:"" });
    setShowAddDevice(false);
    fetchDevices();
  };

  const deleteDevice = async (id) => {
    await fetch(`http://localhost:5000/api/devices/${id}`, { method:"DELETE" });
    fetchDevices();
  };

  const startSniffer = () => {
    if (intervalRef.current) return;
    setRunning(true);
    intervalRef.current = setInterval(async () => {
      try {
        const [logsRes, statsRes] = await Promise.all([
          fetch("http://localhost:5000/api/logs"),
          fetch("http://localhost:5000/api/stats"),
        ]);
        const logsData  = await logsRes.json();
        const statsData = await statsRes.json();
        setLogs(logsData);
        setAttackCount(statsData.attacks);
        setNormalCount(statsData.normal);
        const latest = logsData[0];
        if (latest?.result === "ATTACK") {
          flashGlitch();
          setGridCells((cells) => cells.map((c) => Math.random() < 0.08 ? { ...c, attack:true, active:true } : c));
          setTimeout(() => setGridCells((cells) => cells.map((c) => c.attack ? { ...c, attack:false } : c)), 600);
        }
        setTrendData((old) => [...old.slice(1), latest?.result === "ATTACK" ? 1 : 0]);
      } catch(err) { console.warn("API not reachable:", err); }
    }, 2000);
  };

  const stopSniffer = () => { clearInterval(intervalRef.current); intervalRef.current = null; setRunning(false); };
  const resetAll = () => { stopSniffer(); setLogs([]); setAttackCount(0); setNormalCount(0); setTrendData(Array(30).fill(0)); };
  const downloadCSV = () => {
    const rows = logs.map((l) => `${l.timestamp},${l.src_ip},${l.result},${l.confidence}`).join("\n");
    const blob = new Blob(["timestamp,src_ip,result,confidence\n" + rows], { type:"text/csv" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "detections.csv"; a.click();
  };

  const filteredLogs = filter === "ALL" ? logs : logs.filter((l) => l.result === filter);
  const total = attackCount + normalCount;
  const threatPct = total > 0 ? ((attackCount / total) * 100).toFixed(1) : "0.0";
  const latestStatus = logs[0]?.result ?? "IDLE";
  const trendH = 60;

  return (
    <div style={{ fontFamily:"'Share Tech Mono','Courier New',monospace", background:"#000", minHeight:"100vh", color:"#00ff88", position:"relative", overflow:"hidden" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&display=swap');
        *{box-sizing:border-box;margin:0;padding:0}
        .glitch{animation:glitch 0.3s steps(2) forwards}
        @keyframes glitch{0%{transform:translate(0)}20%{transform:translate(-3px,1px);filter:hue-rotate(90deg)}40%{transform:translate(3px,-1px);filter:hue-rotate(180deg)}60%{transform:translate(-2px,2px)}80%{transform:translate(2px,-2px)}100%{transform:translate(0)}}
        @keyframes pulse-red{0%,100%{opacity:1}50%{opacity:0.4}}
        @keyframes scanline{0%{top:-5%}100%{top:105%}}
        @keyframes blink{0%,100%{opacity:1}50%{opacity:0}}
        @keyframes fadeIn{from{opacity:0;transform:translateX(-8px)}to{opacity:1;transform:translateX(0)}}
        .log-row{animation:fadeIn 0.25s ease forwards}
        .btn{font-family:'Share Tech Mono',monospace;border:1px solid;padding:8px 20px;cursor:pointer;font-size:13px;letter-spacing:1px;text-transform:uppercase;transition:all 0.15s;background:transparent}
        .btn:hover{opacity:0.75}
        .btn-start{color:#00ff88;border-color:#00ff88}.btn-start:hover{background:rgba(0,255,136,0.1)}
        .btn-stop{color:#ff3355;border-color:#ff3355}.btn-stop:hover{background:rgba(255,51,85,0.1)}
        .btn-reset{color:#888;border-color:#444}
        .btn-export{color:#00ccff;border-color:#00ccff}
        .fbtn{font-family:'Share Tech Mono',monospace;padding:5px 14px;border:1px solid #333;background:transparent;color:#555;cursor:pointer;font-size:11px;letter-spacing:1px;transition:all 0.15s}
        .fall{border-color:#00ff88;color:#00ff88;background:rgba(0,255,136,0.08)}
        .fattack{border-color:#ff3355;color:#ff3355;background:rgba(255,51,85,0.08)}
        .fnormal{border-color:#00ccff;color:#00ccff;background:rgba(0,204,255,0.08)}
        input,select{outline:none}
        ::-webkit-scrollbar{width:4px}::-webkit-scrollbar-track{background:#0a0a0a}::-webkit-scrollbar-thumb{background:#1a3a1a;border-radius:2px}
      `}</style>

      {/* Scanline */}
      <div style={{ position:"fixed",left:0,width:"100%",height:"3px",background:"linear-gradient(transparent,rgba(0,255,136,0.06),transparent)",animation:"scanline 4s linear infinite",pointerEvents:"none",zIndex:999 }} />

      {/* Grid */}
      <div style={{ position:"fixed",inset:0,pointerEvents:"none",display:"grid",gridTemplateColumns:`repeat(${GRID_COLS},1fr)`,gridTemplateRows:`repeat(${GRID_ROWS},1fr)`,zIndex:0 }}>
        {gridCells.map((c) => (
          <div key={c.id} style={{ border:"1px solid rgba(0,255,136,0.04)",background:c.attack?"rgba(255,51,85,0.18)":c.active?"rgba(0,255,136,0.04)":"transparent",transition:"background 0.3s" }} />
        ))}
      </div>

      <div style={{ position:"relative",zIndex:1,padding:"24px 28px",maxWidth:"1100px",margin:"0 auto" }}>

        {/* Header */}
        <div style={{ display:"flex",alignItems:"flex-start",justifyContent:"space-between",marginBottom:"24px" }}>
          <div>
            <div style={{ fontSize:"10px",color:"#333",letterSpacing:"4px",marginBottom:"4px" }}>ANTHROPIC · IOT SECURITY · v2.1.0</div>
            <h1 className={glitch?"glitch":""} style={{ fontFamily:"'Orbitron',monospace",fontSize:"28px",fontWeight:900,color:"#00ff88",letterSpacing:"2px",textShadow:"0 0 20px rgba(0,255,136,0.3)" }}>
              CYBER<span style={{ color:"#ff3355" }}>_</span>SHIELD
            </h1>
            <div style={{ fontSize:"11px",color:"#444",letterSpacing:"3px",marginTop:"2px" }}>REAL-TIME IOT INTRUSION DETECTION SYSTEM</div>
          </div>
          <div style={{ textAlign:"right" }}>
            <div style={{ display:"inline-flex",alignItems:"center",gap:"8px",padding:"8px 16px",border:`1px solid ${latestStatus==="ATTACK"?"#ff3355":latestStatus==="NORMAL"?"#00ff88":"#333"}`,background:latestStatus==="ATTACK"?"rgba(255,51,85,0.08)":"rgba(0,255,136,0.06)" }}>
              <div style={{ width:"8px",height:"8px",borderRadius:"50%",background:latestStatus==="ATTACK"?"#ff3355":"#00ff88",animation:latestStatus==="ATTACK"?"pulse-red 0.6s infinite":running?"blink 1.2s infinite":"none" }} />
              <span style={{ fontFamily:"'Orbitron',monospace",fontSize:"12px",color:latestStatus==="ATTACK"?"#ff3355":latestStatus==="NORMAL"?"#00ff88":"#444",letterSpacing:"2px" }}>
                {latestStatus==="ATTACK"?"THREAT DETECTED":latestStatus==="NORMAL"?"SYSTEM SECURE":"STANDBY"}
              </span>
            </div>
            <div style={{ fontSize:"10px",color:"#333",marginTop:"6px",letterSpacing:"2px" }}>{new Date().toLocaleTimeString()} LOCAL</div>
          </div>
        </div>

        {/* Controls */}
        <div style={{ display:"flex",gap:"10px",marginBottom:"20px",flexWrap:"wrap" }}>
          {!running
            ? <button className="btn btn-start" onClick={startSniffer}>▶ START SNIFFER</button>
            : <button className="btn btn-stop"  onClick={stopSniffer}>■ STOP SNIFFER</button>}
          <button className="btn btn-reset"  onClick={resetAll}>↺ RESET</button>
          <button className="btn btn-export" onClick={downloadCSV} disabled={logs.length===0}>↓ EXPORT CSV</button>
          <div style={{ marginLeft:"auto",display:"flex",gap:"6px",alignItems:"center" }}>
            <span style={{ fontSize:"10px",color:"#333",letterSpacing:"2px",marginRight:"4px" }}>FILTER:</span>
            {["ALL","ATTACK","NORMAL"].map((f) => (
              <button key={f} className={`fbtn ${filter===f?`f${f.toLowerCase()}`:""}`} onClick={()=>setFilter(f)}>{f}</button>
            ))}
          </div>
        </div>

        {/* TAB BAR */}
        <div style={{ display:"flex",gap:"0",marginBottom:"20px",borderBottom:"1px solid #111" }}>
          {[
            { key:"dashboard", label:"📡 Dashboard" },
            { key:"devices",   label:"🔌 IoT Devices" },
          ].map((tab) => (
            <button key={tab.key} onClick={()=>setActiveTab(tab.key)} style={{
              fontFamily:"'Orbitron',monospace",padding:"10px 24px",
              background: activeTab===tab.key?"rgba(0,255,136,0.08)":"transparent",
              border:"none",
              borderBottom: activeTab===tab.key?"2px solid #00ff88":"2px solid transparent",
              color: activeTab===tab.key?"#00ff88":"#444",
              cursor:"pointer",fontSize:"11px",letterSpacing:"2px",textTransform:"uppercase"
            }}>{tab.label}</button>
          ))}
        </div>

        {/* ── DASHBOARD TAB ── */}
        {activeTab === "dashboard" && (
          <div>
            {/* Metrics */}
            <div style={{ display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:"12px",marginBottom:"20px" }}>
              {[
                {label:"TOTAL PACKETS",value:total.toLocaleString(),color:"#00ff88"},
                {label:"ATTACKS",value:attackCount.toLocaleString(),color:"#ff3355"},
                {label:"NORMAL",value:normalCount.toLocaleString(),color:"#00ccff"},
                {label:"THREAT LEVEL",value:`${threatPct}%`,color:Number(threatPct)>30?"#ff3355":"#ffaa00"},
              ].map((m) => (
                <div key={m.label} style={{ border:`1px solid ${m.color}22`,padding:"14px 16px",background:`${m.color}06` }}>
                  <div style={{ fontSize:"9px",color:"#444",letterSpacing:"2px",marginBottom:"6px" }}>{m.label}</div>
                  <div style={{ fontSize:"26px",fontFamily:"'Orbitron',monospace",color:m.color,fontWeight:700 }}>{m.value}</div>
                </div>
              ))}
            </div>

            {/* Trend */}
            <div style={{ border:"1px solid #111",padding:"14px 16px",marginBottom:"16px",background:"rgba(0,0,0,0.6)" }}>
              <div style={{ fontSize:"9px",color:"#333",letterSpacing:"3px",marginBottom:"10px" }}>ATTACK TREND — LAST 30 CLASSIFICATIONS</div>
              <svg width="100%" height={trendH} viewBox={`0 0 ${trendData.length*20} ${trendH}`} preserveAspectRatio="none">
                {trendData.map((v,i) => <rect key={i} x={i*20+1} y={v?0:trendH*0.6} width={17} height={v?trendH:trendH*0.4} fill={v?"#ff335566":"#00ff8822"} rx={1} />)}
                {trendData.map((v,i) => <rect key={`t${i}`} x={i*20+1} y={v?0:trendH*0.6} width={17} height={2} fill={v?"#ff3355":"#00ff88"} />)}
              </svg>
              <div style={{ display:"flex",justifyContent:"space-between",fontSize:"9px",color:"#222",marginTop:"4px" }}>
                <span>← 30 PKT AGO</span><span>NOW →</span>
              </div>
            </div>

            {/* Log Table */}
            <div style={{ border:"1px solid #111",background:"rgba(0,0,0,0.7)" }}>
              <div style={{ padding:"10px 16px",borderBottom:"1px solid #111",display:"flex",justifyContent:"space-between",alignItems:"center" }}>
                <span style={{ fontSize:"9px",color:"#333",letterSpacing:"3px" }}>LIVE TRAFFIC FEED — {filteredLogs.length} ENTRIES</span>
                {running && <span style={{ fontSize:"9px",color:"#00ff88",letterSpacing:"2px",animation:"blink 1s infinite" }}>● LIVE</span>}
              </div>
              <div style={{ display:"grid",gridTemplateColumns:"160px 150px 80px 90px",padding:"7px 16px",borderBottom:"1px solid #0a0a0a",fontSize:"9px",color:"#333",letterSpacing:"2px" }}>
                {["TIMESTAMP","SOURCE IP","CONF","STATUS"].map((h)=><span key={h}>{h}</span>)}
              </div>
              <div style={{ maxHeight:"340px",overflowY:"auto" }}>
                {filteredLogs.length===0
                  ? <div style={{ padding:"40px",textAlign:"center",color:"#222",fontSize:"12px",letterSpacing:"3px" }}>{running?"AWAITING PACKETS...":"START SNIFFER TO BEGIN"}</div>
                  : filteredLogs.map((log,i) => (
                    <div key={i} className="log-row" style={{ display:"grid",gridTemplateColumns:"160px 150px 80px 90px",padding:"7px 16px",borderBottom:"1px solid #080808",fontSize:"12px",background:log.result==="ATTACK"?"rgba(255,51,85,0.06)":"transparent" }}>
                      <span style={{ color:"#333",fontSize:"11px" }}>{log.timestamp}</span>
                      <span style={{ color:log.result==="ATTACK"?"#ff6677":"#00ccff" }}>{log.src_ip}</span>
                      <span style={{ color:"#444",fontSize:"11px" }}>{log.confidence}</span>
                      <span style={{ fontFamily:"'Orbitron',monospace",fontSize:"10px",color:log.result==="ATTACK"?"#ff3355":"#00ff88",letterSpacing:"1px" }}>
                        {log.result==="ATTACK"?"⚠ ATTACK":"✓ NORMAL"}
                      </span>
                    </div>
                  ))
                }
              </div>
            </div>
          </div>
        )}

        {/* ── IOT DEVICES TAB ── */}
        {activeTab === "devices" && (
          <div>
            <div style={{ display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"16px" }}>
              <span style={{ fontSize:"9px",color:"#333",letterSpacing:"3px" }}>
                REGISTERED IOT DEVICES — {deviceStats.length} TOTAL
              </span>
              <button className="btn btn-start" onClick={()=>setShowAddDevice(!showAddDevice)}>
                + ADD DEVICE
              </button>
            </div>

            {/* Add Device Form */}
            {showAddDevice && (
              <div style={{ border:"1px solid #00ff8833",padding:"20px",marginBottom:"20px",background:"rgba(0,255,136,0.03)" }}>
                <div style={{ fontSize:"9px",color:"#333",letterSpacing:"3px",marginBottom:"16px" }}>NEW DEVICE REGISTRATION</div>
                <div style={{ display:"grid",gridTemplateColumns:"1fr 1fr",gap:"12px",marginBottom:"16px" }}>
                  {[
                    {label:"DEVICE NAME", key:"name", placeholder:"e.g. Living Room Camera"},
                    {label:"IP ADDRESS",  key:"ip",   placeholder:"e.g. 192.168.1.101"},
                    {label:"LOCATION",    key:"location", placeholder:"e.g. Living Room"},
                  ].map((field) => (
                    <div key={field.key}>
                      <div style={{ fontSize:"9px",color:"#444",letterSpacing:"2px",marginBottom:"6px" }}>{field.label}</div>
                      <input
                        value={newDevice[field.key]}
                        onChange={(e)=>setNewDevice({...newDevice,[field.key]:e.target.value})}
                        placeholder={field.placeholder}
                        style={{ width:"100%",background:"#0a0a0a",border:"1px solid #222",color:"#00ff88",padding:"8px 12px",fontFamily:"'Share Tech Mono',monospace",fontSize:"12px" }}
                      />
                    </div>
                  ))}
                  <div>
                    <div style={{ fontSize:"9px",color:"#444",letterSpacing:"2px",marginBottom:"6px" }}>DEVICE TYPE</div>
                    <select value={newDevice.type} onChange={(e)=>setNewDevice({...newDevice,type:e.target.value})}
                      style={{ width:"100%",background:"#0a0a0a",border:"1px solid #222",color:"#00ff88",padding:"8px 12px",fontFamily:"'Share Tech Mono',monospace",fontSize:"12px" }}>
                      {["Smart Camera","Smart Bulb","Temperature Sensor","Smart Lock","Motion Sensor","Smart Speaker","Router","Other"].map((t)=>(
                        <option key={t} value={t}>{t}</option>
                      ))}
                    </select>
                  </div>
                </div>
                <div style={{ display:"flex",gap:"10px" }}>
                  <button className="btn btn-start" onClick={addDevice}>✓ SAVE DEVICE</button>
                  <button className="btn btn-reset" onClick={()=>setShowAddDevice(false)}>✕ CANCEL</button>
                </div>
              </div>
            )}

            {/* Device Cards */}
            {deviceStats.length === 0 ? (
              <div style={{ padding:"60px",textAlign:"center",color:"#222",border:"1px solid #111",fontSize:"12px",letterSpacing:"3px" }}>
                NO DEVICES REGISTERED — CLICK + ADD DEVICE TO START MONITORING
              </div>
            ) : (
              <div style={{ display:"grid",gridTemplateColumns:"repeat(2,1fr)",gap:"12px" }}>
                {deviceStats.map((d) => (
                  <div key={d.id} style={{ border:`1px solid ${d.status==="THREAT"?"#ff335533":"#00ff8822"}`,padding:"16px",background:d.status==="THREAT"?"rgba(255,51,85,0.05)":"rgba(0,255,136,0.03)" }}>
                    <div style={{ display:"flex",justifyContent:"space-between",marginBottom:"12px" }}>
                      <div>
                        <div style={{ fontFamily:"'Orbitron',monospace",color:"#00ff88",fontSize:"13px" }}>{d.name}</div>
                        <div style={{ fontSize:"10px",color:"#444",marginTop:"2px" }}>{d.type} · {d.location}</div>
                        <div style={{ fontSize:"10px",color:"#333",marginTop:"2px" }}>IP: {d.ip}</div>
                      </div>
                      <div style={{ textAlign:"right" }}>
                        <div style={{ fontSize:"12px",fontFamily:"'Orbitron',monospace",color:d.status==="THREAT"?"#ff3355":"#00ff88" }}>
                          {d.status==="THREAT"?"⚠ THREAT":"✓ SECURE"}
                        </div>
                        <button onClick={()=>deleteDevice(d.id)} style={{ background:"transparent",border:"1px solid #222",color:"#444",cursor:"pointer",fontSize:"10px",marginTop:"8px",padding:"3px 8px",fontFamily:"'Share Tech Mono',monospace" }}>
                          ✕ REMOVE
                        </button>
                      </div>
                    </div>
                    <div style={{ display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:"8px" }}>
                      {[
                        {label:"TOTAL PKTS", value:d.total,   color:"#00ff88"},
                        {label:"NORMAL",     value:d.normal,  color:"#00ccff"},
                        {label:"ATTACKS",    value:d.attacks, color:"#ff3355"},
                      ].map((m)=>(
                        <div key={m.label} style={{ background:"rgba(0,0,0,0.4)",padding:"8px",textAlign:"center" }}>
                          <div style={{ fontSize:"8px",color:"#333",letterSpacing:"2px",marginBottom:"4px" }}>{m.label}</div>
                          <div style={{ fontSize:"18px",fontFamily:"'Orbitron',monospace",color:m.color }}>{m.value}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        <div style={{ marginTop:"14px",display:"flex",justifyContent:"space-between",fontSize:"9px",color:"#222",letterSpacing:"2px" }}>
          <span>ANN MODEL · 6-FEATURE CLASSIFIER · BINARY CLASSIFICATION</span>
          <span>SEM 6 · DEEP LEARNING PROJECT · 2026</span>
        </div>
      </div>
    </div>
  );
}