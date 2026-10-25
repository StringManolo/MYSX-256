# Exact hull check of the beam trails at R = 15–17 (PAPER.md §4.10.4, "next step")

New tools (all in `misc/`): `hull_bidir.py` (exact budgeted hull, meet-in-the-middle),
`scan_endpairs.py` (hull of the top-K end-mask pairs of a beam), `test_signed_dp.py`
(validation against `propagate()`), `emp_check.py` (empirical correlation vs the real cipher).
Inputs: `beam_paths_bwd20.json`, `beam_paths_fwd23.json` (re-runs of `mysx_linear_beam.py run`
for offset 20 backward and offset 23 forward, `--paths 15..22`; their `ub` values and the
R=14/20/24 paths are identical to the saved `beam_bwd.json` / `beam_full.json`).

## Method

`hull_count.py` expands only forward, so it explodes when heavy rounds sit at the start of the
trail. `hull_bidir.py` grows a forward frontier from the start mask `u` and a backward frontier
from the end mask `v` (always the smaller one), prunes with the minimum weight already paid by
the opposite frontier, and streams the last round into the join. Any trail `u -> v` of weight
`<= wmax` has prefix and suffix weight `<= wmax`, so the result is **complete for weight <= wmax**
(only `b = 0xFFFFFFFF` cells are skipped, irrelevant below weight 15). With `--keys K` it also sums
the exact signed contributions (cell sign from `corr_Z`, key sign `(-1)^{m.rk}`) for K keys.

## Validation

- `mysx_linear_beam.py selftest`: PASSED (20 s).
- Signed hull vs `propagate()` of `mysx_linear_model.py`: 40/40 end masks equal exactly
  (windows r0=12 R=10,11,12 and r0=27 R=10, two keys, `python3 test_signed_dp.py`).
- R=14 offset-20 backward: 1 trail of weight 5, same as `hull_count.py`.

## Results

`w1` = single-trail weight of the beam trail. "budget" = `wmax` (all trails up to it enumerated).
Hull value identical for keys `rand_key(1000)` and `rand_key(1001)`.

| trail | R | rounds | w1 | trails u→v found | budget | exact hull |
|---|---|---|---|---|---|---|
| offset 20 bwd | 14 | 100–113 | 5 | 1 × w5 | 7 | ±2^-5 (isolated) |
| offset 20 bwd | 15 | 99–113 | 8 | 2 × w8 | 10 | **+2^-7** (2 trails add) |
| offset 20 bwd | 16 | 98–113 | 12 | 2 × w12 | 14 | **+2^-11** (2 trails add) |
| offset 20 bwd | 17 | 97–113 | 16 | 2 × w16 | 18 | **0** (exact cancellation) |
| offset 23 fwd | 15 | 23–37 | 8 | 4 × w8 | 10 | 0 |
| offset 23 fwd | 16 | 23–38 | 8 | 4 × w8 | 10 | 0 |
| offset 23 fwd | 17 | 23–39 | 14 | 4 × w14 | 16 | 0 |

Empirical check against the real cipher (fixed key `rand_key(1000)`):

- offset 20 bwd, R=16, N=2^28: corr = **+6.06e-4 ± 6.1e-5**. Hull prediction 4.88e-4 (+1.9σ),
  single-trail prediction 2.44e-4 (+5.9σ), zero (+9.9σ). The sign matches the model.
- offset 23 fwd, R=16, N=2^24: corr = +3.7e-4 ± 2.4e-4 (1.5σ from zero); the single-trail value
  would be ±3.9e-3 (16σ away). Consistent with the cancellation.

R=17 end-pair scan (`scan_endpairs.py --R 17`, `scan_R17.log`): the top-8 end pairs of offset 20
bwd (w16; 7 computed, 1 exceeded the state cap) and of offset 23 fwd (w14; 8/8) all cancel
exactly. Offsets 19 bwd, 24 fwd, 3 bwd, 2 bwd have R=17 weights 23–26 and exceeded the state
cap (800k): undecided.

## What this establishes

- The offset-20 backward window gives a verified linear distinguisher up to **R=16 (rounds
  98–113) with |corr| = 2^-11** (≈2^22 texts), a factor 2 above the single-trail value at R=15
  and R=16. Previously certified: R=14.
- At R=17 the beam's best end pairs of both offsets cancel, so the single-trail weights at R≥17
  are not distinguisher lengths for these pairs (same phenomenon as r0=23/24 in §4.10.3).

## What it does not establish

- Trails of weight above the budget are not counted (≥15 at R=16, ≥19 at R=17). The empirical
  value is 1.9σ above the hull prediction, compatible with noise but not a proof that nothing
  heavier contributes.
- R≥18 is undecided: with weight 24 the frontiers exceed 2.5M states. Only end pairs the beam
  returned were tried; other pairs at R=17–22 may not cancel. Covering them needs a different
  method (the SAT/MILP hull encoding of `LINEAR_MODEL.md` §7) or a larger top-K scan.
- Sign checked empirically for one key only. No key-recovery cost, no lower bound.

## Suggested edits (not applied)

- PAPER §4.10.3/§4.10.4, §8, §10, abstract and README: "14-round window (rounds 100–113)" →
  "16-round window (rounds 98–113, |corr| = 2^-11)"; first "Not established" bullet becomes
  "R≥17 undecided; the beam's R=17 pairs cancel".
- README repository tree: add the four scripts and the two JSON files above.

## Reproduce

```bash
cd misc
python3 test_signed_dp.py
python3 hull_bidir.py beam_paths_bwd20.json 20 --R 16 --wmax 14 --keys 2
python3 hull_bidir.py beam_paths_bwd20.json 20 --R 17 --wmax 18 --keys 2
python3 hull_bidir.py beam_paths_fwd23.json 23 --R 16 --wmax 10 --keys 2
python3 emp_check.py beam_paths_bwd20.json 20 16 28 1000      # ~12 min, 1 CPU
python3 scan_endpairs.py --R 17 --cells 20:backward,23:forward --topk 8
```
