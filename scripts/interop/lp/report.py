#!/usr/bin/env python3
"""Compare the L1 raw responses of two servers byte for byte (proof hex normalized) and print a table
of every result line.  usage: report.py results BASE_SERVER LP_SERVER"""
import json, sys, glob, os
d, a, b = sys.argv[1], sys.argv[2], sys.argv[3]
def load(s):
    out = {}
    for l in open(os.path.join(d, f"{s}-rust.jsonl")):
        r = json.loads(l)
        if r.get("scenario") == "L1":
            out[r["kind"]] = (r["http"], r["body"])
    return out
A, B = load(a), load(b)
same = diff = 0
for k in sorted(set(A) | set(B)):
    if A.get(k) == B.get(k):
        same += 1
        print(f"IDENTICAL {k}")
    else:
        diff += 1
        print(f"DIFFERENT {k}\n  {a}: {A.get(k)}\n  {b}: {B.get(k)}")
print(f"L1: {same} identical, {diff} different of {same+diff} request kinds ({a} vs {b})")
