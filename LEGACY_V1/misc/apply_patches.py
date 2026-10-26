#!/usr/bin/env python3
"""Apply restoration patches to PAPER.md. Idempotent: re-running is safe.
Each patch is exact-string match. If a patch doesn't apply, it is SKIPPED
with a message so you can inspect manually."""
from pathlib import Path
import sys

for candidate in [Path("/root/MYSX-256/PAPER.md"), Path("../PAPER.md"), Path("PAPER.md")]:
    if candidate.exists():
        PATH = candidate
        break
else:
    print("ERROR: PAPER.md not found", file=sys.stderr); sys.exit(1)

text = PATH.read_text()
print(f"Patching {PATH.resolve()} ({len(text)} bytes)")

patches = [
# 1: §1.1 non-objectives - restore 6-10 round specificity
("""- resistance to integral attacks beyond the distinguishers reported in
  §4.9, nor resistance to impossible-differential, boomerang, or
  algebraic attacks (none analyzed);""",
"""- resistance to integral attacks beyond the 6–10 round distinguishers
  reported in §4.9 (offset-dependent; 6 rounds at r0=0, 10 rounds at
  r0=15), nor resistance to impossible-differential, boomerang, or
  algebraic attacks (none analyzed);"""),

# 2: §1.4 "New direction" - restore checkpoint values note
("""  from both directions. The table of §4.10.2 is the minimum over
  forward and backward and over all offsets.""",
"""  from both directions. The table of §4.10.2 is now the minimum over
  forward and backward and over all offsets; a few `v0.1-draft`
  checkpoint values (R=12, R=48, R=112, R=128, and in general those
  where backward wins) are superseded."""),

# 3: §1.4 "New verified distinguisher" - restore hull_count + seven weighted rounds
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

# 4: §1.4 "Correction on R=128" - restore forward-mode note
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

# 5: §3.2 r=4 closure - restore "MILP model is correct within a factor of 2"
("""**Ratio: 2.00×.** This measurement was made at r0=0; the clustering
factor at other offsets has not been measured (§3.4).""",
"""**Ratio: 2.00×.**

The trail exists at r=4. The single-trail probability is a factor 2
higher than the MILP predicts, consistent with the clustering factor
documented in §3.3. **The MILP model is correct within a factor of 2
at this round count.** This measurement was made at r0=0; the
clustering factor at other offsets has not been measured (§3.4)."""),

# 6: §3.2 linear comparison - restore historical note about superseded conclusion
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

# 7: §4.10.2 footnote - restore full caveat + weight<32 line
("""† The weight-8 trail of this row cancels once its hull is computed (four
trails of weight 8 with the same end masks sum to zero, §4.10.5), so 2¹⁶
texts is not a distinguisher cost. The best certified correlation at
R=16 is the offset-20 backward hull, |corr| = 2⁻¹¹.

Largest R with an achievable single trail of weight < 64 (≈2¹²⁸
texts): **22** (weight 63 at R=22, offset 23 forward; 49 at R=21).
This is a tie with the threshold: "≈20–22 rounds" is the defensible
statement.""",
"""† The weight-8 trail of this row cancels once its hull is computed (four
trails of weight 8 with the same end masks sum to zero, §4.10.5), so 2¹⁶
texts is not a distinguisher cost. The best certified correlation at
R=16 is the offset-20 backward hull, |corr| = 2⁻¹¹ (≈2²² texts). The
same caveat applies to every row: a row is an achievable *single-trail*
weight, not a correlation.

Largest R with an achievable single trail of weight < 32 (≈2⁶⁴ texts):
**19**. Largest R with weight < 64 (≈2¹²⁸ texts): **22** (weight 63 at
R=22, offset 23 forward; 49 at R=21). This is a **tie with the
threshold**: at beam 1000 the same cell gives 64/71, so the defensible
statement is "≈20–22 rounds", not "22"."""),

# 8: §4.10.4 - restore "Key recovery" not-established bullet
("""- That multi-bit starts do not help at all. The tested samples
  (pairs47, rand:5000:4) do not improve on single-bit, but the random
  sample is too small to rule out structured multi-bit masks that
  might. The honest statement is "the multi-bit starts tested do not
  improve on single-bit".""",
"""- That multi-bit starts do not help at all. The tested samples
  (pairs47, rand:5000:4) do not improve on single-bit, but the random
  sample is too small to rule out structured multi-bit masks that
  might. The honest statement is "the multi-bit starts tested do not
  improve on single-bit".
- Key recovery from any hull, differential analogues, and the effect
  of the final whitening and of key-recovery rounds around a
  distinguisher."""),

# 9: §7 - restore "preliminary" qualifier
("""particular 2-branch Feistel structure and its key schedule; the MYSX
integral distinguishers in §4.9 are considerably shorter, and their""",
"""particular 2-branch Feistel structure and its key schedule; the
preliminary MYSX integral distinguishers in §4.9 are considerably
shorter, and their"""),
]

applied = 0
skipped = 0
failed = 0
for i, (before, after) in enumerate(patches, 1):
    n = text.count(before)
    if n == 0:
        print(f"[SKIP {i}] pattern not found (already applied, or context differs)")
        skipped += 1
        continue
    if n > 1:
        print(f"[FAIL {i}] pattern found {n} times — ambiguous, skipping")
        failed += 1
        continue
    text = text.replace(before, after, 1)
    print(f"[OK   {i}] patched")
    applied += 1

PATH.write_text(text)
print("=" * 60)
print(f"Applied: {applied}  Skipped: {skipped}  Failed: {failed}")
if failed:
    print("Some patches failed. Inspect the file and fix manually.")
    sys.exit(1)
print("Done.")
