#!/usr/bin/env python3
"""
run_nist.py — Non-interactive wrapper for NIST STS 2.1.2.

Prerequisites:
  pip install pexpect
  NIST STS built at ./sts-2.1.2/assess (run `make` first)

Feeds the interactive prompts automatically:
  - Generator: 0 (Input File)
  - Input file: ./nist_input/all_data.bin
  - All tests: 1
  - Parameter adjustments: 0 (no)
  - Bitstreams: 100
  - Input mode: 1 (binary)
"""
import os, sys, pexpect, subprocess

STS = "./sts-2.1.2/assess"
INPUT = "./misc/nist_input/all_data.bin"
N_BITS = 1000000
N_STREAMS = 100

def main():
    if not os.path.exists(STS):
        sys.exit(f"ERROR: {STS} not found. Run `make` in sts-2.1.2/ first.")
    if not os.path.exists(INPUT):
        sys.exit(f"ERROR: {INPUT} not found. Run `misc/gen_nist_input.js` first.")

    child = pexpect.spawn(STS, [str(N_BITS)], timeout=3600, encoding="utf-8")
    child.logfile = sys.stdout

    child.expect("Enter choice:")
    child.sendline("0")                       # Input File

    child.expect("User Prescribed Input File:")
    child.sendline(os.path.abspath(INPUT))

    child.expect("Enter Choice:")
    child.sendline("1")                       # All tests

    child.expect("Select Test:")
    child.sendline("0")                       # no parameter adjustments

    child.expect("How many bitstreams?")
    child.sendline(str(N_STREAMS))

    child.expect("Select input mode:")
    child.sendline("1")                       # binary

    child.expect(pexpect.EOF, timeout=3600)
    child.close()

    report = "sts-2.1.2/experiments/AlgorithmTesting/finalAnalysisReport.txt"
    if os.path.exists(report):
        print(f"\nReport: {report}")
        # Busca FAIL / * en el reporte
        text = open(report).read()
        fails = text.count("FAIL") + text.count("*")
        print(f"FAIL/* occurrences: {fails}")
        sys.exit(0 if fails == 0 else 1)
    sys.exit(0)

if __name__ == "__main__":
    main()
