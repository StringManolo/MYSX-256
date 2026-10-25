#!/usr/bin/env python3
"""Apply 3 remaining patches to PAPER.md (misc). Idempotent."""
from pathlib import Path
import sys

PATH = Path("PAPER.md")
if not PATH.exists():
    print("ERROR: PAPER.md not found in current directory", file=sys.stderr)
    sys.exit(1)

text = PATH.read_text()
print(f"Patching {PATH.resolve()} ({len(text)} bytes)")

patches = [
# A: §1.1 non-objectives - 6-10 round specificity
("""- resistance to integral attacks beyond the distinguishers reported in
  §4.9, nor resistance to impossible-differential, boomerang, or
  algebraic attacks (none analyzed);""",
"""- resistance to integral attacks beyond the 6–10 round distinguishers
  reported in §4.9 (offset-dependent; 6 rounds at r0=0, 10 rounds at
  r0=15), nor resistance to impossible-differential, boomerang, or
  algebraic attacks (none analyzed);"""),

# B: §3.2 Ratio - restore "The trail exists at r=4" paragraph
("""**Ratio: 2.00×.** This measurement was made at r0=0; the clustering
factor at other offsets has not been measured (§3.4).""",
"""**Ratio: 2.00×.**

The trail exists at r=4. The single-trail probability is a factor 2
higher than the MILP predicts, consistent with the clustering factor
documented in §3.3. **The MILP model is correct within a factor of 2
at this round count.** This measurement was made at r0=0; the
clustering factor at other offsets has not been measured (§3.4)."""),

# C: §3.2 Comparison with linear - v0.1-draft conclusion superseded
("""The differential direction has a deterministic 13-round chain (r0=10,
§3.5), which in data cost (1 pair) is stronger than the linear
distinguisher, but is 3 rounds shorter. Neither direction is
uniformly dominant; both peak at different offsets.""",
"""The differential direction has a deterministic 13-round chain (r0=10,
§3.5), which in data cost (1 pair) is stronger than the linear
distinguisher, but is 3 rounds shorter. Neither direction is
uniformly dominant; both peak at different offsets. The v0.1-draft
conclusion that "the linear direction is the weaker one by a wide
margin" is superseded: the gap noted there was not intrinsic (the
linear figure is the minimum over all 31 rotation offsets, while the
differential figure was for one input at one position)."""),
]

applied = 0
for i, (before, after) in enumerate(patches, 1):
    n = text.count(before)
    if n == 0:
        print(f"[SKIP {i}] pattern not found (already applied or context differs)")
        continue
    if n > 1:
        print(f"[FAIL {i}] pattern found {n} times — ambiguous, skipping")
        sys.exit(1)
    text = text.replace(before, after, 1)
    print(f"[OK   {i}] patched")
    applied += 1

PATH.write_text(text)
print("=" * 60)
print(f"Applied: {applied}")
if applied == 3:
    print("ALL 3 patches applied. PAPER.md is now complete.")
else:
    print("Some patches skipped. Inspect manually if needed.")
