#!/usr/bin/env python3
"""Live presence dashboard: one page, either the simulator or the real board as its feed.

`--source sim` replays csi_sim's scripted room so the whole stack can be exercised without
credentials; `--source serial` reads COM6 exactly like csi_presence.py does. Both paths run
the same parse_line() and Detector, so what the page shows for sim is the same computation
that will run on air.

Rendering stays on 2D canvas with no filters: this box has a WDDM-1.2 GeForce 210 and
Electron/Chrome fall back to SwiftShader, so WebGL and CSS blur are expensive here.
"""
import argparse
import json
import os
import queue
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import serial

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from csi_presence import Detector, app_mode_reset, parse_line, provision  # noqa: E402
import csi_sim  # noqa: E402

HEAT_COLS = 180       # packets in the heatmap


class Declined(Exception):
    """Provisioning was dismissed or failed outright; re-prompting every 2s would be hostile."""


class Server(ThreadingHTTPServer):
    """A browser tab closing mid-stream aborts the socket, which would print a stack trace."""

    def handle_error(self, request, client_address):
        if not isinstance(sys.exc_info()[1],
                         (ConnectionAbortedError, ConnectionResetError, BrokenPipeError)):
            super().handle_error(request, client_address)

HTML = r"""<!doctype html>
<html><head><meta charset="utf-8"><title>ESP32 CSI presence</title>
<style>
 body{margin:0;background:#0d1117;color:#e6edf3;font:13px/1.45 ui-monospace,Consolas,monospace}
 header{display:flex;align-items:center;gap:14px;padding:10px 16px;border-bottom:1px solid #21262d}
 h1{font-size:14px;margin:0;font-weight:600;letter-spacing:.4px}
 #badge{padding:4px 14px;border-radius:4px;font-weight:700;letter-spacing:1px}
 .empty{background:#1c2a1c;color:#7ee787}.present{background:#3d1414;color:#ff7b72}
 .cal{background:#1f2733;color:#79c0ff}
 #simtag{padding:3px 9px;border:1px solid #6b4400;border-radius:4px;color:#e3b341;font-weight:700}
 #simtag.live{border-color:#1f6f3f;color:#7ee787}
 main{padding:14px 16px;display:grid;gap:14px}
 .card{border:1px solid #21262d;border-radius:6px;padding:10px}
 .card h2{margin:0 0 8px;font-size:12px;font-weight:600;color:#8b949e;letter-spacing:.6px}
 canvas{display:block;width:100%;height:200px;image-rendering:pixelated}
 #heat{height:180px}
 #stats{display:flex;flex-wrap:wrap;gap:18px;color:#8b949e}
 #stats b{color:#e6edf3;font-weight:600}
 #event{color:#e3b341;font-weight:700}
 #why{color:#8b949e;font-size:12px}
 #recal{background:#16212b;color:#79c0ff;border:1px solid #2d4356;border-radius:4px;
       padding:3px 10px;font:inherit;cursor:pointer}
 #recal:hover{background:#1d2c38}
 #note{color:#8b949e;max-width:1000px}
 #toast{min-height:18px;font-weight:600}
</style></head><body>
<header><h1>ESP32 CSI PRESENCE</h1><span id="badge" class="cal">LOADING</span>
 <span id="why"></span><span id="simtag">SIMULATED</span><span id="clock"></span>
 <button id="recal" title="learn a fresh empty-room baseline">re-calibrate</button></header>
<main>
 <div id="toast"></div>
 <div class="card"><h2>Motion: normalised shape jitter vs thresholds (log scale)</h2>
  <canvas id="jit" height="200"></canvas></div>
 <div class="card"><h2>Occupancy: distance from the empty-room shape - this is what a still
  person looks like</h2><canvas id="offset" height="120"></canvas></div>
 <div class="card"><h2>Subcarrier amplitude over time (rows = valid carriers)</h2>
  <canvas id="heat" height="180"></canvas></div>
 <div class="card"><h2>Session</h2><div id="stats"></div></div>
 <div id="note"></div>
</main>
<script>
const JIT=document.getElementById('jit'), HEAT=document.getElementById('heat');
const OFT=document.getElementById('offset');
const HEAT_COLS=__HEAT_COLS__;
const RING=1200;   // jitter samples kept on screen: 24 s at 50 Hz
const OFF=document.createElement('canvas'); OFF.width=HEAT_COLS; OFF.height=42;
const O=OFF.getContext('2d'); O.fillStyle='#0d1117'; O.fillRect(0,0,OFF.width,OFF.height);
let jit=[], off=[], state=[], cfg={fs:50, carriers:null}, last=null, fps=0;

// Bitmap tracks the CSS box at 1:1. Deliberately not scaled by devicePixelRatio: on this
// box the GPU path is SwiftShader, and halving the fill is worth more than crisper lines.
function fit(c){const w=Math.max(80,Math.floor(c.clientWidth)),h=Math.max(60,Math.floor(c.clientHeight));
 if(c.width!==w)c.width=w; if(c.height!==h)c.height=h; return c;}
function color(v,mx){const t=mx>0?v/mx:0;const g=Math.round(30+180*Math.pow(t,0.6));
 return `rgb(${Math.round(g*0.35)},${g},${Math.round(g*0.95)})`;}

function setText(id,v){const e=document.getElementById(id); if(e.textContent!==v) e.textContent=v;}
function paintBadge(){
 if(!last){setText('badge','WAITING'); document.getElementById('badge').className='cal'; return;}
 const s = last.phase==='calibrate' ? 'CALIBRATING' : (last.present ? 'PRESENT' : 'EMPTY');
 setText('badge',s);
 document.getElementById('badge').className = last.phase==='calibrate'?'cal':(last.present?'present':'empty');
 // Which gate fired matters: motion says someone is moving, occupancy says someone is there
 // even at rest. A room can be one without being the other.
 setText('why', last.phase==='calibrate' ? '' :
  (last.moving && last.shifted ? 'moving + occupying' : last.moving ? 'moving' :
   last.shifted ? 'sitting still' : 'no gate tripped'));
}
function paintStats(){
 if(!last) return;
 setText('stats', `packets ${last.rows} | seq gaps ${last.drops} | receiver skips ${last.skips}`
  + ` | jitter ${last.jitter==null?'-':last.jitter.toFixed(4)} vs enter ${last.enter==null?'-':last.enter.toFixed(4)}`
  + ` | displacement ${last.offset==null?'-':last.offset.toFixed(4)} vs gate ${last.ref_enter==null?'-':last.ref_enter.toFixed(4)}`
  + ` | valid carriers ${last.valid==null?'-':last.valid}`
  + ` | rssi ${last.rssi} dBm | ch ${last.ch} | gain ${last.gain.toFixed(2)}`
  + ` | ${last.phase}` + (last.event ? ` | scenario: ${last.event}` : ''));
 setText('clock', new Date(last.wall*1000).toLocaleTimeString());
}

function draw(){
 for(const c of [JIT,OFT,HEAT]) fit(c);
 const W=JIT.width,H=JIT.height,g=JIT.getContext('2d');
 g.fillStyle='#0d1117'; g.fillRect(0,0,W,H);
 if(last&&last.enter!=null&&jit.length>1){
  const lg=Math.log10, lo=lg(Math.max(1e-5,Math.min(...jit)*0.8)),
        hi=lg(Math.max(...jit,last.enter)*1.3);
  const y=v=>H-((lg(Math.max(v,1e-6))-lo)/(hi-lo))*H;
  const x=i=>i*(W/(jit.length-1));
  g.strokeStyle='#30363d'; g.lineWidth=1; g.fillStyle='#545c66';
  for(let p=Math.ceil(lo);p<=Math.floor(hi);p++){const yy=y(10**p);
   g.beginPath();g.moveTo(0,yy);g.lineTo(W,yy);g.stroke();
   g.fillText(10**p>=0.001?(10**p).toString():10**p.toExponential(0),3,yy-2);}
  g.strokeStyle='#f0883e';g.beginPath();g.moveTo(0,y(last.enter));g.lineTo(W,y(last.enter));g.stroke();
  g.strokeStyle='#db4d4f';g.beginPath();g.moveTo(0,y(last.exit));g.lineTo(W,y(last.exit));g.stroke();
  g.fillStyle='rgba(255,123,114,0.13)';
  for(let i=0;i<jit.length;i++) if(state[i]){let j=i;
   while(j<jit.length&&state[j])j++; g.fillRect(x(i),0,Math.max(1.5,x(j-1)-x(i)),H); i=j;}
  g.strokeStyle='#58a6ff';g.lineWidth=1.2;g.beginPath();
  for(let i=0;i<jit.length;i++){i?g.lineTo(x(i),y(jit[i])):g.moveTo(x(i),y(jit[i]));}
  g.stroke(); g.lineWidth=1;
  for(let i=0;i<jit.length;i++) if(state[i]){g.fillStyle='#ff7b72';
   g.fillRect(x(i)-0.8,y(jit[i])-0.8,2,2);}
  g.fillStyle='#f0883e'; g.fillText('enter '+last.enter.toFixed(5), 6, y(last.enter)-4);
  g.fillStyle='#db4d4f'; g.fillText('exit '+last.exit.toFixed(5), 6, y(last.exit)+10);
 }
 const ow=OFT.width,oh=OFT.height,og=OFT.getContext('2d');
 og.fillStyle='#0d1117'; og.fillRect(0,0,ow,oh);
 if(last&&last.ref_enter!=null&&off.length>1){
  const lg=Math.log10, lo=lg(Math.max(1e-4,Math.min(...off,last.ref_exit)*0.8)),
        hi=lg(Math.max(...off,last.ref_enter)*1.4);
  const y2=v=>oh-((lg(Math.max(v,1e-5))-lo)/(hi-lo))*oh;
  const x2=i=>i*(ow/(off.length-1));
  og.strokeStyle='#30363d'; og.lineWidth=1; og.fillStyle='#545c66';
  for(let p=Math.ceil(lo);p<=Math.floor(hi);p++){const yy=y2(10**p);
   og.beginPath();og.moveTo(0,yy);og.lineTo(ow,yy);og.stroke();
   og.fillText((10**p).toFixed(2),3,yy-2);}
  og.strokeStyle='#2fbcd6';og.beginPath();og.moveTo(0,y2(last.ref_enter));og.lineTo(ow,y2(last.ref_enter));og.stroke();
  og.strokeStyle='#1c6472';og.beginPath();og.moveTo(0,y2(last.ref_exit));og.lineTo(ow,y2(last.ref_exit));og.stroke();
  og.fillStyle='rgba(255,123,114,0.13)';
  for(let i=0;i<off.length;i++) if(state[i]){let j=i;
   while(j<off.length&&state[j])j++; og.fillRect(x2(i),0,Math.max(1.5,x2(j-1)-x2(i)),oh); i=j;}
  og.strokeStyle='#d0d7de';og.lineWidth=1.2;og.beginPath();
  for(let i=0;i<off.length;i++){i?og.lineTo(x2(i),y2(off[i])):og.moveTo(x2(i),y2(off[i]));}
  og.stroke(); og.lineWidth=1;
  og.fillStyle='#2fbcd6'; og.fillText('occupancy gate '+last.ref_enter.toFixed(4), 6, y2(last.ref_enter)-4);
  og.fillStyle='#7ee0ef'; og.fillText(last.shifted?'occupied':'matches empty room', ow-190, 12);
 }
 const hc=HEAT.getContext('2d'); hc.imageSmoothingEnabled=false;
 hc.clearRect(0,0,HEAT.width,HEAT.height);
 hc.drawImage(OFF,0,0,HEAT.width,HEAT.height);
}
setInterval(()=>{const t0=performance.now();draw();fps=fps*0.85+(1000/Math.max(1,performance.now()-t0))*0.15;},50);

const es=new EventSource('/stream'+location.search);
es.onmessage=e=>{const d=JSON.parse(e.data);
 if(d.type==='end'){es.close(); return;}
 if(d.hello){cfg=Object.assign(cfg,d.hello);
  document.getElementById('note').textContent=d.hello.note;
  if(cfg.sim) document.getElementById('recal').style.display='none'; return;}
 if(d.type==='note'){const t=document.getElementById('toast');
  t.textContent=d.text; t.style.color=d.kind==='err'?'#ff7b72':'#79c0ff';
  clearTimeout(t._h); t._h=setTimeout(()=>t.textContent='',9000); return;}
 if(d.type!=='packet') return;
 last=d; paintBadge(); paintStats();
 if(!cfg.sim){const t=document.getElementById('simtag'); t.className='live'; t.textContent='LIVE AIR';}
 if(d.jitter!=null){jit.push(d.jitter); off.push(d.offset==null?0:d.offset); state.push(d.present?1:0);
  if(jit.length>RING){jit.shift(); off.shift(); state.shift();}}
 if(d.amp&&cfg.carriers){O.drawImage(OFF,-1,0); const mx=Math.max(...d.amp,1);
  for(let i=0;i<cfg.carriers.length;i++){const k=cfg.carriers[i];
   O.fillStyle=color(d.amp[k],mx); O.fillRect(HEAT_COLS-1,i,1,1);}}
};
document.getElementById('recal').onclick=async()=>{
 try{ await fetch('/recal',{method:'POST'});
  setText('toast','re-calibrating: leave the room and stay still for 12 s'); }
 catch(e){ setText('toast','re-calibrate request failed','err'); }
};
paintBadge();   // marker: if the badge stays LOADING, inline JS is not running at all
</script></body></html>"""

PAGE = HTML.replace("__HEAT_COLS__", str(HEAT_COLS))


class Hub:
    """Fan-out of one producer to any number of browser tabs."""

    def __init__(self):
        self.subs = []
        self.lock = threading.Lock()
        self.rows = self.drops = 0
        self.last_seq = None
        self.recal = threading.Event()

    def subscribe(self):
        q = queue.Queue(maxsize=200)
        with self.lock:
            self.subs.append(q)
        return q

    def unsubscribe(self, q):
        with self.lock:
            if q in self.subs:
                self.subs.remove(q)

    def publish(self, rec):
        with self.lock:
            subs = list(self.subs)
        for q in subs:
            try:
                q.put_nowait(rec)
            except queue.Full:
                pass      # a stalled tab must never back up the radio

    def note(self, text, kind="info"):
        self.publish({"type": "note", "kind": kind, "text": text, "wall": time.time(),
                      "rows": self.rows, "drops": self.drops})


def feed_serial(hub, det, port, baud, calibrate, do_reset):
    sp = serial.Serial(port, baud, timeout=1)
    try:
        if do_reset:
            app_mode_reset(sp)
            if not provision(sp):
                raise Declined("board reported no IP - 201/no AP means the wrong band or "
                               "spelling, a handshake timeout means the wrong passphrase")
        deadline = time.time() + calibrate
        while True:
            if hub.recal.is_set():
                hub.recal.clear()
                det.reset()
                deadline = time.time() + calibrate
                hub.note(f"re-calibrating: empty room, no movement, for {calibrate:.0f} s")
            raw = sp.readline()
            if not raw:
                continue
            p = parse_line(raw.decode("utf-8", "replace").strip())
            if not p:
                continue
            seq, rssi, chn, amp = p
            if hub.last_seq is not None and seq != hub.last_seq + 1:
                hub.drops += max(0, seq - hub.last_seq - 1)
            hub.last_seq = seq
            hub.rows += 1
            active, jit = det.push(amp, rssi)
            phase = "calibrate" if det.valid is None else "live"
            if phase == "calibrate" and time.time() >= deadline:
                k, base = det.finalize_calibration()
                hub.note(f"baseline set: {k} valid carriers, empty-room jitter {base:.5f}")
            hub.publish({"type": "packet", "wall": time.time(), "seq": seq, "rssi": rssi,
                         "ch": chn, "jitter": jit, "present": bool(active),
                         "moving": bool(det.active), "shifted": bool(det.displaced),
                         "offset": None if det.offset is None else round(det.offset, 5),
                         "ref_enter": None if det.ref_enter is None else round(det.ref_enter, 5),
                         "ref_exit": None if det.ref_exit is None else round(det.ref_exit, 5),
                         "phase": phase, "rows": hub.rows, "drops": hub.drops,
                         "skips": det.skips, "enter": det.enter, "exit": det.exit,
                         "baseline": det.baseline, "valid": None if det.valid is None
                         else int(det.valid.sum()), "gain": 1.0,
                         "amp": [round(float(x), 1) for x in amp]})
    finally:
        sp.close()


def feed_sim(hub, det, fs, factor, seed):
    for line, meta in csi_sim.frames(factor=factor, fs=fs, seed=seed):
        p = parse_line(line)
        if p is None:
            continue
        seq, rssi, chn, amp = p
        hub.rows += 1
        active, jit = det.push(amp, rssi)
        phase = "calibrate" if det.valid is None else "live"
        if phase == "calibrate" and hub.rows >= int(fs * 12):
            k, base = det.finalize_calibration()
            hub.note(f"baseline set: {k} valid carriers, empty-room jitter {base:.5f}, "
                     f"displacement gate {det.ref_enter:.5f}")
        hub.publish({"type": "packet", "wall": time.time(), "seq": seq, "rssi": rssi,
                     "ch": chn, "jitter": jit, "present": bool(active),
                     "moving": bool(det.active), "shifted": bool(det.displaced),
                     "offset": None if det.offset is None else round(det.offset, 5),
                     "ref_enter": None if det.ref_enter is None else round(det.ref_enter, 5),
                     "ref_exit": None if det.ref_exit is None else round(det.ref_exit, 5),
                     "phase": phase,
                     "rows": hub.rows, "drops": hub.drops, "skips": det.skips,
                     "enter": det.enter, "exit": det.exit, "baseline": det.baseline,
                     "valid": None if det.valid is None else int(det.valid.sum()),
                     "gain": meta["gain"], "event": meta["event"],
                     "amp": [round(float(x), 1) for x in amp]})


def make_handler(hub, cfg):
    class H(BaseHTTPRequestHandler):
        # HTTP/1.1 chunked keep-alive: on the default 1.0 Chrome buffers the whole
        # text/event-stream response and EventSource never fires.
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _send(self, body, ctype):
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if urlparse(self.path).path == "/recal":
                hub.recal.set()
                self._send(b"re-calibrating", "text/plain")
            else:
                self.send_error(404)

        def do_GET(self):
            route = urlparse(self.path).path
            if route == "/":
                self._send(PAGE.encode(), "text/html; charset=utf-8")
            elif route == "/stream":
                # ?burst=N closes the stream after N packets, which freezes the page and lets
                # a headless screenshot (or a shareable capture) finish instead of hanging.
                burst = int((parse_qs(urlparse(self.path).query).get("burst") or [0])[0])
                q = hub.subscribe()
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                sent = 0
                try:
                    self.wfile.write(b"data: " + json.dumps({"hello": cfg}).encode() + b"\n\n")
                    self.wfile.flush()
                    while True:
                        try:
                            rec = q.get(timeout=15)
                        except queue.Empty:
                            self.wfile.write(b": keepalive\n\n")
                            self.wfile.flush()
                            continue
                        self.wfile.write(b"data: " + json.dumps(rec).encode() + b"\n\n")
                        self.wfile.flush()
                        if rec.get("type") == "packet":
                            sent += 1
                            if burst and sent >= burst:
                                self.wfile.write(b'data: {"type":"end"}\n\n')
                                self.wfile.flush()
                                break
                except OSError:
                    # Includes WinError 10053 ConnectionAbortedError when a tab just goes away.
                    pass
                finally:
                    hub.unsubscribe(q)
            else:
                self.send_error(404)
    return H


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", choices=["sim", "serial"], default="sim")
    ap.add_argument("--http-port", type=int, default=8760)
    ap.add_argument("--port", default="COM6")
    ap.add_argument("--baud", type=int, default=460800)
    ap.add_argument("--calibrate", type=float, default=12.0)
    ap.add_argument("--fs", type=float, default=50.0)
    ap.add_argument("--factor", type=float, default=1.0,
                    help="sim only: compress wall-clock, timestamps stay at --fs")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--no-provision", action="store_true")
    args = ap.parse_args()

    hub = Hub()
    det = Detector()
    if args.source == "sim":
        note = ("SIMULATED RADIO. The channel model is real multipath plus Doppler, but no "
                "packet came from your room. Parser, gain rejection and thresholds are the "
                "same code the live board uses.")
    else:
        note = ("LIVE. Streaming CSI from " + args.port + " at " + str(args.baud) +
                " baud. Keep the room empty and still during the calibration window.")
    cfg = {"sim": args.source == "sim", "fs": args.fs, "note": note,
           "carriers": [int(k) for k in csi_sim.VALID]}

    srv = Server(("127.0.0.1", args.http_port), make_handler(hub, cfg))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"dashboard: http://127.0.0.1:{args.http_port}/  source={args.source}")

    runner = (lambda: feed_sim(hub, det, args.fs, args.factor, args.seed)) if \
        args.source == "sim" else \
        (lambda: feed_serial(hub, det, args.port, args.baud, args.calibrate,
                             not args.no_provision))
    try:
        while True:
            try:
                runner()
            except KeyboardInterrupt:
                raise
            except Declined as e:
                print(f"provisioning stopped: {e}")
                hub.note(f"provisioning stopped: {e}", "err")
                try:
                    input("press Enter here to ask the board again, Ctrl+C to quit: ")
                except (EOFError, OSError):
                    threading.Event().wait()   # idle without spinning, but keep serving the page
            except Exception as e:
                print(f"feed stopped: {e!r}; restarting in 2s")
                hub.note(f"feed stopped: {e!r}", "err")
                time.sleep(2)
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
