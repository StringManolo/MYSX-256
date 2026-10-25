name: Deep search (MYSX calendars)

on:
  workflow_dispatch:
    inputs:
      n_per_job:
        description: 'Candidatos por job'
        default: '100000'
        required: true
      seeds:
        description: 'Seeds (JSON list)'
        default: '[1,2,3,4,5,6,7,8,9,10]'
        required: true

jobs:
  search:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        seed: ${{ fromJSON(github.event.inputs.seeds) }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Run deep search
        run: |
          cd cryptanalysis/DMITM
          python3 search_mysx_deep.py \
            --n ${{ github.event.inputs.n_per_job }} \
            --seed ${{ matrix.seed }} \
            --out deep_seed${{ matrix.seed }}.json
      - uses: actions/upload-artifact@v4
        with:
          name: deep-seed-${{ matrix.seed }}
          path: cryptanalysis/DMITM/deep_seed${{ matrix.seed }}.json
          retention-days: 7

  merge:
    needs: search
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/download-artifact@v4
        with:
          path: artifacts
          pattern: deep-seed-*
      - name: Merge and rank
        run: |
          python3 - <<'EOF'
          import json, glob
          cands = []
          for f in glob.glob('artifacts/**/deep_seed*.json', recursive=True):
              cands.extend(json.load(open(f)))
          cands.sort(key=lambda x: (x['dmitm'], x['chain31'], x['chain10']))
          with open('top_all.json', 'w') as f:
              json.dump(cands, f, indent=0)
          print(f"Total: {len(cands)} candidates")
          print(f"dmitm distribution:")
          from collections import Counter
          print(Counter(c['dmitm'] for c in cands))
          print("\nTop 20:")
          for c in cands[:20]:
              print(f"  dmitm={c['dmitm']:2d} chain31={c['chain31']} {c['name']}")
          EOF
      - uses: actions/upload-artifact@v4
        with:
          name: top-all
          path: top_all.json
          retention-days: 30
