"""Simulate what ransomware does to a directory, to test Redoubt's detector.

Operates only on the isolated lab directory passed in. It rewrites files that
the harness created moments ago with random bytes - the same observable
behaviour as encryption, without any encryption and without any real payload.

    python simulate.py <lab-dir> [seconds]

`seconds` spreads the work over that long, so the run spans several of the
detector's sampling windows. A very fast run is also a valid test: the correct
answer there is for Redoubt to name nobody rather than a bystander.
"""

import os
import sys
import time

lab = sys.argv[1]
duration = float(sys.argv[2]) if len(sys.argv) > 2 else 0.0

entries = sorted(os.listdir(lab))
files = [f for f in entries if os.path.isfile(os.path.join(lab, f))]
print(f"targets in {lab}: {len(files)}")

pause = (duration / max(1, len(files))) if duration else 0.0
rewritten = 0
touched_decoy = None

for name in files:
    path = os.path.join(lab, name)

    # High-entropy content, exactly as an encrypted file would look. Written
    # in place with r+b so a read-only or hidden attribute does not change the
    # outcome the way a truncating open would.
    size = max(65536, os.path.getsize(path))
    with open(path, "r+b") as f:
        f.write(os.urandom(size))
        f.truncate(size)
        f.flush()
        os.fsync(f.fileno())
    rewritten += 1

    if "redoubt" in name.lower():
        touched_decoy = name

    if name.endswith(".txt"):
        os.replace(path, path + ".locky")

    if pause:
        time.sleep(pause)

note = os.path.join(lab, "HOW_TO_DECRYPT.txt")
with open(note, "w") as f:
    f.write("Your files have been encrypted.\n(Redoubt test. Nothing is encrypted.)\n")

print(f"rewritten     : {rewritten}")
print(f"decoy touched : {touched_decoy}")
print(f"ransom note   : {os.path.basename(note)}")
print(f"our pid       : {os.getpid()}")
