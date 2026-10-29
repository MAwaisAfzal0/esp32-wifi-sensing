"""Offline self-test for csi_presence.py using SYNTHETIC CSI (no radio involved)."""
import sys
import numpy as np

sys.path.insert(0, "sensing/tools")
from csi_presence import parse_line, Detector

N_SC = 54                      # ESP32 legacy L-LTF, 20 MHz
NULLS = {0, 1, 2, 3, 4, 5, 6, 31, 32, 51, 52, 53}   # guard / DC / pilot


def amps(shape, gain=1.0):
    return (shape * gain).astype(np.float32)


def to_line_vals(a):
    vals = []
    for v in a:
        q = int(np.clip(v * 0.7, -127, 127))
        vals += [q, q]
    return vals


def line(seq, a, rssi=-45, ch=6):
    vals = to_line_vals(a)
    return (f'CSI_DATA,{seq},58:2a:bd:7c:a7:78,{rssi},7,0,7,1,1,0,0,0,1,0,-96,0,'
            f'{ch},0,{1000 + seq},0,63,0,{len(vals)},0,"[{",".join(map(str, vals))}]"')


def new_base(rng):
    b = (1.0 + 0.15 * rng.random(N_SC)).astype(np.float32)
    for k in NULLS:
        b[k] = 0.0
    return b


def main():
    rng = np.random.default_rng(7)
    base = new_base(rng)

    # 1. wire format
    seq, rssi, ch, amp = parse_line(line(0, amps(base)))
    assert (seq, rssi, ch) == (0, -45, 6)
    assert len(amp) == N_SC
    assert (amp[list(NULLS)] == 0).all()
    print(f"parse OK: {N_SC} subcarriers, {len(to_line_vals(amp))} int8 values, rssi={rssi} ch={ch}")

    # 2. empty room: subcarrier-level noise only, no body
    det = Detector()
    for _ in range(200):
        noisy = base * (1.0 + 0.02 * rng.standard_normal(N_SC))
        det.push(amps(noisy, max(0.2, 1.0 + 0.3 * rng.standard_normal())))
    n_valid, base_j = det.finalize_calibration()
    assert n_valid == N_SC - len(NULLS), (n_valid, N_SC - len(NULLS))
    print(f"calibrate OK: {n_valid} valid subcarriers, empty-room jitter={base_j:.5f}, "
          f"enter>{det.enter:.5f}")

    still_empty = [det.push(amps(base * (1 + 0.02 * rng.standard_normal(N_SC)),
                                max(0.2, 1 + 0.3 * rng.standard_normal())))[1]
                   for _ in range(50)]
    st = det.active
    print(f"room still empty: jitter={np.mean(still_empty):.5f}, state={'PRESENT' if st else 'empty'}")
    assert st is False, "quiet room must not trigger"

    # 3. gain-only AGC step (the design point): 8x level, channel unchanged
    d2 = Detector()
    for _ in range(200):
        d2.push(amps(base * (1 + 0.02 * rng.standard_normal(N_SC)),
                     max(0.2, 1 + 0.3 * rng.standard_normal())))
    d2.finalize_calibration()
    trips = sum(1 for _ in range(80)
                if d2.push(amps(base * (1 + 0.02 * rng.standard_normal(N_SC)), 8.0))[0])
    print(f"pure 8x gain step: {trips}/80 packets flagged PRESENT (want 0) jitter={d2.jitter:.5f}")
    assert trips == 0, "gain-only change must not be reported as presence"

    # 4. body moving through the field: multipath shape changes packet to packet
    for i in range(120):
        moved = base * (1.0 + 0.35 * rng.standard_normal(N_SC))
        active, jit = det.push(amps(moved, max(0.2, 1 + 0.3 * rng.standard_normal())))
        if i == 119:
            print(f"body moving: jitter={jit:.5f} enter={det.enter:.5f} "
                  f"state={'PRESENT' if active else 'empty'}")
    assert det.active is True, "moving body must be flagged"

    print("\nALL SELF-TESTS PASSED (synthetic data only, nothing measured over the air)")


if __name__ == "__main__":
    main()
