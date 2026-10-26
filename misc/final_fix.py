#!/usr/bin/env python3
"""Apply the 3 remaining §1.4 restorations to PAPER.md (misc)."""
from pathlib import Path
import sys

PATH = Path("PAPER.md")
if not PATH.exists():
    print("ERROR: PAPER.md not found in misc/", file=sys.stderr); sys.exit(1)

text = PATH.read_text()
print(f"Patching {PATH.resolve()} ({len(text)} bytes)")

patches = [
# P1: "is now the minimum" (cosmetic but consistent with v0.1-draft)
("""  from both directions. The table of §4.10.2 is the minimum over
  forward and backward and over all offsets; a few `v0.1-draft`
  checkpoint values (R=12, R=48, R=112, R=128, and in general those
  where backward wins) are superseded.""",
"""  from both directions. The table of §4.10.2 is now the minimum over
  forward and backward and over all offsets; a few `v0.1-draft`
  checkpoint values (R=12, R=48, R=112, R=128, and in general those
  where backward wins) are superseded."""),

# P2: "hull_count = 1 trail" + "It consists of seven weighted rounds..."
("""- **New verified linear distinguisher (on a 16-round window):** the
  offset-20 backward trail is isolated in its hull at R=14 (weight 5,
  rounds 100–113, empirical correlation matching 2⁻⁵) and, by the
  exact budgeted hull of §4.10.5, extends to R=16 (rounds 98–113,
  |corr| = 2⁻¹¹). This is the first non-trivial linear distinguisher
  the analysis certifies.""",
"""- **New verified linear distinguisher (on a 16-round window):** the
  offset-20 backward trail is isolated in its hull at R=14 (weight 5,
  rounds 100–113, `hull_count` = 1 trail, empirical correlation 2⁻⁵
  on the real cipher, §4.10.3) and, by the exact budgeted hull of
  §4.10.5, extends to R=16 (rounds 98–113, |corr| = 2⁻¹¹). This is
  the first non-trivial linear distinguisher the analysis certifies.
  It consists of seven weighted rounds (98–104, total weight 12)
  followed by a 9-round weight-0 chain (105–113)."""),

# P3: "in forward mode..." + "The v0.1-draft statement..."
("""- **Correction on R=128:** in backward mode, offset 3 gives
  `end_round(3) = 127`, `realizable_R = 128`, so the combined R=128 =
  2248 at offset 3 backward is a real trail inside the cipher, not a
  virtual extension.""",
"""- **Correction on R=128:** in forward mode only r0=0 fits a 128-round
  trail. In backward mode, offset 3 gives `end_round(3) = 127`,
  `realizable_R = 128`, so the combined R=128 = 2248 at offset 3
  backward **is a real trail inside the cipher**, not a virtual
  extension. The `v0.1-draft` statement that "for r0>0 the value at
  R=128 is a virtual extension" is forward-specific; §4.10.2
  clarifies."""),
]

applied = 0
for i, (before, after) in enumerate(patches, 1):
    n = text.count(before)
    if n == 0:
        print(f"[SKIP P{i}] pattern not found (context differs)")
        continue
    if n > 1:
        print(f"[FAIL P{i}] pattern found {n} times — ambiguous")
        sys.exit(1)
    text = text.replace(before, after, 1)
    print(f"[OK   P{i}] patched")
    applied += 1

PATH.write_text(text)
print("=" * 60)
print(f"Applied: {applied}/3")
if applied == 3:
    print("All 3 patches applied. PAPER.md (misc) is complete.")
else:
    print("Some patches skipped. Inspect manually if needed.")
