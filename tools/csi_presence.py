#!/usr/bin/env python3
"""Capture ESP32 router-CSI over serial and decide room presence.

The classic ESP32 has no AGC/FFT gain compensation (see app_main.c CONFIG_GAIN_CONTROL),
so absolute amplitudes are unusable. Presence is decided from the per-packet normalized
subcarrier *shape*, which is invariant to receiver gain steps.
"""
import argparse
import csv
import getpass
import json
import math
import re
import sys
import time

import numpy as np
import serial

BRACKET = re.compile(r"\[([-0-9,\s]+)\]")


def parse_line(line):
    """Return (seq, rssi, channel, amp_vector) or None if not a CSI row."""
    if not line.startswith("CSI_DATA,"):
        return None
    m = BRACKET.search(line)
    if not m:
        return None
    try:
        vals = [int(v) for v in m.group(1).split(",") if v.strip() != ""]
    except ValueError:
        return None  # serial byte loss mid-row; skip rather than kill a long capture
    if len(vals) < 4:
        return None
    fields = next(csv.reader([line]))
    try:
        rssi = int(fields[3])
        channel = int(fields[16])
        seq = int(fields[1])
    except (ValueError, IndexError):
        rssi, channel, seq = 0, 0, 0
    n = len(vals) // 2
    z = np.empty(n, dtype=np.complex64)
    for i in range(n):
        z[i] = complex(vals[2 * i + 1], vals[2 * i])
    return seq, rssi, channel, np.abs(z)


class Detector:
    """Presence from consecutive-packet shape jitter.

    Each packet's valid-subcarrier amplitude vector is unit-normalised, which removes the
    receiver gain term the ESP32 cannot compensate for. Jitter is 1 - cos(angle) between
    successive normalised packets: an empty room is electromagnetically quiet, a body moving
    through the multipath field makes consecutive packets disagree. A frozen-vs-baseline
    comparison was tried first and is wrong here, since it silently adapts away slow change.
    """

    def __init__(self, alpha=0.25):
        self.alpha = alpha
        self.prev = None
        self.jitter = None
        self.valid = None
        self.baseline = None
        self.baseline_std = None
        self.enter = None
        self.exit = None
        self.active = False
        self.last_rssi = None
        self.last_norm = None
        self.skips = 0
        self.samples = 0
        # Second, motion-independent gate: distance from the empty-room shape (see push).
        self.ref = None
        self.offset = None
        self.displaced = False
        self.ref_enter = None
        self.ref_exit = None

    @staticmethod
    def _unit(v):
        n = np.linalg.norm(v)
        return v / n if n > 0 else v

    def reset(self):
        """Forget the learned room and collect a fresh calibration window."""
        self.__init__(alpha=self.alpha)

    def _shape(self, amp):
        if self.valid is None:
            return None
        return self._unit(amp[self.valid])

    def observe(self, amp):
        """Update valid-mask/jitter accumulators during calibration. Returns nothing."""
        if self.valid is None:
            self._cal_stack = getattr(self, "_cal_stack", [])
            self._cal_stack.append(amp.copy())

    def push(self, amp, rssi=None):
        """Feed one packet. Returns (state, jitter) once calibrated.

        Two things can make consecutive packets disagree without the room changing, and both
        come from the receiver rather than the channel: a reported-rssi step (the AP switched
        rate/tx power) and a jump in total amplitude, which is an AGC gain step. Unit
        normalisation already cancels a *steady* gain offset, but the transition itself also
        moves the int8 quantization noise, which does bend the normalized shape. So the
        transition packet is dropped instead of scored.
        """
        self.samples += 1

        stepped = rssi is not None and self.last_rssi is not None \
            and abs(rssi - self.last_rssi) >= 6
        if rssi is not None:
            self.last_rssi = rssi

        norm = float(np.linalg.norm(amp))
        jumped = (self.last_norm is not None and norm > 0 and
                  (self.last_norm > 1.25 * norm or norm > 1.25 * self.last_norm))
        if norm > 0:
            self.last_norm = norm

        if stepped or jumped:
            self.skips = getattr(self, "skips", 0) + 1
            if jumped:
                self.prev = None      # rebuild continuity from the new gain state
            return self.active, self.jitter

        if self.valid is None:
            self.observe(amp)
            return None, None

        x = self._shape(amp)
        if x is None or not np.any(x):
            return self.active, self.jitter

        j = 0.0 if self.prev is None else float(1.0 - np.dot(x, self.prev))
        self.prev = x
        self.jitter = j if self.jitter is None else (self.alpha * j + (1 - self.alpha) * self.jitter)

        # Offset is the other half of the picture: jitter needs the shape to keep moving, so a
        # person who sits still decays back into the empty-room signature. Displacing the field
        # does not, because the reflections are now different, not merely changing.
        d = float(np.linalg.norm(x - self.ref))
        self.offset = d if self.offset is None else (self.alpha * d + (1 - self.alpha) * self.offset)

        if self.enter is None:
            return self.active, self.jitter

        self.active = self.jitter > (self.exit if self.active else self.enter)
        if self.ref_enter is not None:
            self.displaced = self.offset > (self.ref_exit if self.displaced else self.ref_enter)
        return (self.active or self.displaced), self.jitter

    def finalize_calibration(self):
        """Call once the empty-room window is done. Returns (n_valid, baseline_jitter)."""
        stack = np.stack(getattr(self, "_cal_stack", []))
        if len(stack) < 2:
            raise RuntimeError("not enough calibration packets")
        self.valid = np.median(stack, axis=0) > 0
        unit = np.stack([self._unit(r[self.valid]) for r in stack])
        js = np.array([0.0] + [1.0 - float(np.dot(unit[i], unit[i - 1]))
                               for i in range(1, len(unit))])
        self.jitter = float(js[-1])
        self.prev = unit[-1]
        self.baseline = float(js.mean())
        self.baseline_std = float(js.std())
        # Enter at 4 sigma over the empty-room jitter, exit back below 2 sigma.
        self.enter = self.baseline + 4.0 * self.baseline_std + 1e-4
        self.exit = self.baseline + 2.0 * self.baseline_std + 5e-5

        # Displacement gate. Relative floors because the two scale-free sigma terms collapse
        # when an empty room is very quiet, and real air noise is ~150x the model's.
        self.ref = self._unit(unit.mean(axis=0))
        dev = np.linalg.norm(unit - self.ref, axis=1)
        self.offset = float(dev[-1])
        self.displaced = False
        dm, ds = float(dev.mean()), float(dev.std())
        self.ref_enter = max(dm + 4.0 * ds, 1.5 * dm)
        self.ref_exit = max(dm + 2.0 * ds, 1.2 * dm)
        return int(self.valid.sum()), self.baseline


def app_mode_reset(sp):
    """Pulse EN with GPIO0 released so the board boots the app, not the ROM loader."""
    sp.dtr = False
    sp.rts = True
    time.sleep(0.1)
    sp.rts = False
    time.sleep(0.1)
    sp.dtr = False


def ask_credentials():
    """Return (ssid, passphrase), or None if the operator declines.

    Console stdin is tried first. A dashboard launched detached from a shell has no readable
    stdin, so input() raises EOFError there; a modal dialog is the only prompt that still works.
    """
    try:
        print("\nboard is asking for credentials:")
        ssid = input("  2.4 GHz SSID (must contain no spaces): ").strip()
        if not ssid:
            return None
        pwd = getpass.getpass("  passphrase (hidden, sent only to the board): ")
        # No echo means a CapsLock or layout slip is invisible, so confirm its length instead.
        print(f"  sending SSID {ssid!r} with a {len(pwd)}-character passphrase")
        return ssid, pwd
    except (EOFError, OSError):
        return _ask_credentials_gui()


def _ask_credentials_gui():
    import tkinter as tk
    from tkinter import simpledialog
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    try:
        ssid = simpledialog.askstring("ESP32 CSI provisioning",
                                      "2.4 GHz SSID (must contain no spaces):", parent=root)
        if not ssid or not ssid.strip():
            return None
        pwd = simpledialog.askstring("ESP32 CSI provisioning",
                                     "Passphrase - sent over USB to the board only, never stored:",
                                     show="*", parent=root) or ""
        return ssid.strip(), pwd
    finally:
        root.destroy()


def provision(sp, prompt_wait=180.0, join_wait=45.0):
    """Answer the firmware's boot prompt so the caller never handles the passphrase.

    protocol_examples_common in stdin mode reads ONE space-separated line
    "<ssid> <password>" (see wifi_connect.c) and does not persist it, so this has to
    share the port opening with the capture loop.

    Two clocks, not one: time spent typing at the prompt must not count against the
    association attempt, or a careful typist always gets a false "no IP".
    """
    deadline = time.time() + prompt_wait
    asked = False
    while time.time() < deadline:
        raw = sp.readline()
        if not raw:
            continue
        line = raw.decode("utf-8", "replace").strip()
        if not line:
            continue
        low = line.lower()
        if "please input ssid password" in low:
            asked = True
            creds = ask_credentials()
            if creds is None:
                print("no credentials supplied; not provisioning again automatically.")
                return False
            ssid, pwd = creds
            if " " in ssid or " " in pwd:
                print("  NOTE: the firmware splits this line on spaces; a space will truncate it.")
            sp.write(f"{ssid} {pwd}\r\n".encode())
            deadline = time.time() + join_wait
            continue
        if "got ip" in low and re.search(r"\d{1,3}(?:\.\d{1,3}){3}", line):
            # "Got IPv6 ... LINK_LOCAL" also contains "got ip"; only a dotted quad means usable.
            print(f"connected: {line}")
            return True
        if "reason" in low or low.startswith("state:"):
            # 201 = no such AP (wrong band or spelling); a handshake timeout = wrong passphrase.
            print(f"  board says: {line}")
        elif asked and ("request ssid" in low or "retry" in low):
            print("board is retrying; it will prompt again.")
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default="COM6")
    ap.add_argument("--baud", type=int, default=460800)
    ap.add_argument("--calibrate", type=float, default=12.0)
    ap.add_argument("--seconds", type=float, default=0.0)
    ap.add_argument("--jsonl", default="sensing_log.jsonl")
    ap.add_argument("--csv", default="sensing_csi.csv")
    ap.add_argument("--no-provision", action="store_true",
                    help="board is already connected; skip the reset + credential prompt")
    args = ap.parse_args()

    sp = serial.Serial(args.port, args.baud, timeout=1)
    det = Detector()
    t_end = time.time() + args.seconds if args.seconds else None
    cf = open(args.csv, "w", newline="")
    cw = csv.writer(cf)
    cw.writerow(["t", "seq", "rssi", "channel", "jitter", "state", "amplitudes"])
    jf = open(args.jsonl, "w")

    stat = {"rows": 0, "dropped": 0, "last_seq": None}
    calibrated = False
    cal_start = time.time()
    print(f"opened {args.port} @ {args.baud}")
    if not args.no_provision:
        app_mode_reset(sp)
        if not provision(sp):
            print("ERROR: board never reported an IP. Check the SSID is 2.4 GHz and that "
                  "the passphrase is correct, then rerun.")
            return 2
    cal_start = time.time()
    print(f"collecting {args.calibrate:.0f}s empty-room baseline...")
    print("KEEP THE ROOM EMPTY AND STILL during calibration.")

    try:
        while True:
            if t_end and time.time() > t_end:
                break
            raw = sp.readline()
            if not raw:
                continue
            try:
                line = raw.decode("utf-8", "replace").strip()
            except Exception:
                continue
            p = parse_line(line)
            if not p:
                continue
            seq, rssi, channel, amp = p
            stat["rows"] += 1
            if stat["last_seq"] is not None and seq != stat["last_seq"] + 1:
                stat["dropped"] += seq - stat["last_seq"] - 1
            stat["last_seq"] = seq
            now = time.time()

            if not calibrated:
                det.push(amp, rssi)
                if now - cal_start >= args.calibrate:
                    n_valid, base_j = det.finalize_calibration()
                    calibrated = True
                    print(f"baseline: {n_valid} valid subcarriers, "
                          f"empty-room jitter={base_j:.5f} "
                          f"(enter>{det.enter:.5f}, exit<{det.exit:.5f})")
                continue

            active, jit = det.push(amp, rssi)
            state = "PRESENT" if active else "empty"
            cw.writerow([round(now, 3), seq, rssi, channel, round(jit, 5), state,
                         " ".join(f"{x:.1f}" for x in amp)])
            rec = {"t": round(now, 3), "seq": seq, "rssi": rssi, "ch": channel,
                   "jitter": round(jit, 5), "state": state}
            jf.write(json.dumps(rec) + "\n")
            jf.flush()
            print(f"\r{state:7s} jitter={jit:.5f} enter={det.enter:.5f} "
                  f"rssi={rssi:4d} ch={channel:2d} rows={stat['rows']} "
                  f"drops={stat['dropped']} "
                  f"gain-skips={det.skips}          ", end="")
    except KeyboardInterrupt:
        pass
    finally:
        jf.close()
        cf.close()
        sp.close()
        print(f"\nclosed. rows={stat['rows']} seq-gaps={stat['dropped']}")


if __name__ == "__main__":
    sys.exit(main())
