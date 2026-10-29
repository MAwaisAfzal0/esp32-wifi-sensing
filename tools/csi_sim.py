#!/usr/bin/env python3
"""Physics-shaped ESP32 CSI simulator that emits real wire-format lines.

Not a random-number generator: it models 2.4 GHz multipath as a sum of delayed taps
(the static room) plus reflectors whose path length changes when a body moves, so
subcarrier phasors rotate at 4*pi*v/lambda. Packet rate and speed therefore set the
achievable jitter, exactly as on hardware.

Output is the classic-ESP32 `CSI_DATA,...` CSV row from csi_recv_router, so anything
downstream consumes it through the same parse_line() and Detector as the real board.
Only the radio is simulated here, never the pipeline.
"""
import argparse
import json
import time

import numpy as np

N_SUB = 54                       # LLTF carriers reported by the classic ESP32
VALID = np.array([k for k in range(N_SUB) if k not in
                  (list(range(0, 7)) + [26, 27] + list(range(51, 54)))])
K_CENTER = np.arange(N_SUB) - (N_SUB // 2)
DELTA_F = 312.5e3                # subcarrier spacing
LAMBDA = 0.1247                  # m at 2.437 GHz
ROUTER_MAC = "aa:bb:cc:dd:ee:01"

# (event, duration_s, body speed m/s, body present)
TIMELINE = [
    ("empty",                 12.0, 0.0,   False),   # calibration window
    ("empty",                  8.0, 0.0,   False),
    ("walk_in",                6.0, 1.2,   True),
    ("sitting_still",         14.0, 0.004, True),    # chest excursion only
    ("pacing",                10.0, 0.8,   True),
    ("sitting_still",          8.0, 0.004, True),
    ("agc_step_while_still",   8.0, 0.004, True),    # receiver raises gain 2x
    ("walk_out",               6.0, 1.2,   False),
    ("empty",                 10.0, 0.0,   False),
]
LOOP_S = sum(d for _, d, _, _ in TIMELINE)


class Channel:
    def __init__(self, seed=7, fs=50.0, snr_db=26.0):
        rng = np.random.default_rng(seed)
        self.fs, self.rng = fs, rng
        self.t = 0.0
        self.seq = 0
        self.rssi = -46.0
        self.gain = 1.0
        self.body = 0.0
        self.speed = 0.0
        self.event = "empty"
        self.ref_scale = None

        self.st_a = np.array([1.0, 0.62, 0.44, 0.31, 0.20, 0.13])
        self.st_tau = np.array([0.0, 45e-9, 95e-9, 160e-9, 240e-9, 330e-9])
        self.st_p = rng.uniform(0, 2 * np.pi, self.st_a.size)

        self.bd = rng.uniform(1.6, 3.8, 3)            # reflector distance, m
        self.b_a = rng.uniform(0.25, 0.60, 3)
        self.b_tau = rng.uniform(380e-9, 720e-9, 3)
        self.b_p = rng.uniform(0, 2 * np.pi, 3)
        self.b_dir = rng.uniform(-1.0, 1.0, 3)        # radial share of the motion
        self.b_tone = rng.uniform(0.22, 0.34, 3)      # respiration, Hz
        self.b_ph = rng.uniform(0, 2 * np.pi, 3)
        self.noise = 10 ** (-snr_db / 20.0)

    def _response(self, offset):
        h = np.zeros(N_SUB, dtype=np.complex128)
        for a, tau, p in zip(self.st_a, self.st_tau, self.st_p):
            h += a * np.exp(1j * p) * np.exp(-2j * np.pi * K_CENTER * DELTA_F * tau)
        for a, tau, p, d in zip(self.b_a, self.b_tau, self.b_p, self.bd + offset):
            h += (a * self.body * np.exp(1j * (p - 4 * np.pi * d / LAMBDA)) *
                  np.exp(-2j * np.pi * K_CENTER * DELTA_F * tau))
        h[np.setdiff1d(np.arange(N_SUB), VALID)] = 0.0
        return h

    def set_event(self, event, speed, present, t_in, dur):
        self.event, self.speed = event, speed
        # Body share ramps continuously toward its target. Ramping from zero at every event
        # boundary instead made each boundary look like a person walking in, which is not
        # what these events are meant to test.
        target = 1.0 if present else 0.0
        if event == "walk_out":
            target = max(0.0, min(1.0, (dur - t_in) / 0.8))
        rate = (1.0 / self.fs) / 0.8
        self.body += float(np.clip(target - self.body, -rate, rate))
        # AGC step: the link reads ~10 dB weaker, so the receiver raises gain one step while
        # the room itself is unchanged. That scale jump is the artifact normalization must eat.
        step = event == "agc_step_while_still" and t_in > dur / 2
        self.gain = 2.0 if step else 1.0
        self.rssi = -56.0 if step else -46.0

    def packet(self):
        self.t += 1.0 / self.fs
        self.seq += 1
        breath = 0.002 * np.sin(2 * np.pi * self.b_tone * self.t + self.b_ph)
        self.bd += (self.speed * self.b_dir) / self.fs
        h = self._response(breath if self.body > 0 else 0.0)
        # Additive receiver noise, not multiplicative: a deep multipath null still reads a
        # few counts on real hardware, which is why the valid-subcarrier mask works.
        h += (np.median(np.abs(h)) * self.noise *
              (self.rng.standard_normal(N_SUB) + 1j * self.rng.standard_normal(N_SUB)) /
              np.sqrt(2))
        h[np.setdiff1d(np.arange(N_SUB), VALID)] = 0.0

        amp = np.abs(h) * self.gain
        # The int8 full-scale reference is fixed for the run, like real hardware: a gain
        # step must genuinely push carriers toward saturation, not be renormalised away.
        if self.ref_scale is None:
            self.ref_scale = np.percentile(amp[VALID], 99) + 1e-9
        amp = np.clip(np.round(127.0 * amp / self.ref_scale), 0, 127)
        self.rssi += self.rng.normal(0, 0.3)
        return amp.astype(np.int64), {"seq": self.seq, "event": self.event,
                                      "gain": self.gain, "speed": self.speed,
                                      "rssi": int(np.clip(self.rssi, -90, -20))}

    def line(self, amp, meta):
        """Encode as the csi_recv_router row: interleaved imag,real int8 pairs."""
        pairs = np.zeros(2 * N_SUB, dtype=np.int64)
        mag = amp.astype(float)
        ph = self.rng.uniform(0, 2 * np.pi, N_SUB)
        pairs[1::2] = np.clip(np.round(mag * np.sin(ph)), -128, 127)
        pairs[0::2] = np.clip(np.round(mag * np.cos(ph)), -128, 127)
        fields = ["CSI_DATA", meta["seq"], ROUTER_MAC, meta["rssi"], 2, 0, 0, 0, 1,
                  0, 0, 0, 0, 0, -95, 0, 6, 0, int(self.t * 1e6) % 2 ** 32, 0,
                  pairs.size, 0, pairs.size, 0, '"[%s]"' % ",".join(map(str, pairs))]
        return ",".join(map(str, fields))


def frames(factor=1.0, seed=7, fs=50.0, loops=0):
    """Yield (wire_line, meta). factor>1 compresses wall-clock only, not timestamps."""
    ch = Channel(seed=seed, fs=fs)
    sleep = 1.0 / (fs * factor)
    n = 0
    while loops == 0 or n < loops:
        n += 1
        for event, dur, speed, present in TIMELINE:
            for s in range(int(round(dur * fs))):
                ch.set_event(event, speed, present, s / fs, dur)
                amp, meta = ch.packet()
                yield ch.line(amp, meta), meta
                if sleep:
                    time.sleep(sleep)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dump", type=int, default=0, help="print N lines and exit")
    ap.add_argument("--quiet", action="store_true", help="just count frames per event")
    ap.add_argument("--factor", type=float, default=1.0)
    ap.add_argument("--loops", type=int, default=1)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    if args.dump:
        for i, (line, meta) in enumerate(frames(factor=1e9, seed=args.seed,
                                                 loops=args.loops)):
            print(line)
            if i + 1 >= args.dump:
                return 0
        return 0

    tally = {}
    for line, meta in frames(factor=args.factor, seed=args.seed, loops=args.loops):
        tally[meta["event"]] = tally.get(meta["event"], 0) + 1
        if not args.quiet:
            print(f'\r{meta["event"]:22s} seq={meta["seq"]:5d} gain={meta["gain"]:.0f} '
                  f'speed={meta["speed"]:.3f} rssi={meta["rssi"]:4d}   ', end="", flush=True)
    if args.quiet:
        print(json.dumps(tally))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
