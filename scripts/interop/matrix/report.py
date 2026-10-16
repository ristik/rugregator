#!/usr/bin/env python3
"""Turn results/*.jsonl into the markdown matrix: python3 report.py results/ > results/matrix.md"""
import glob, json, os, sys

d = sys.argv[1] if len(sys.argv) > 1 else "results"
rows = {}
servers, clients = [], []
for f in sorted(glob.glob(os.path.join(d, "*-*.jsonl"))):
    s, c = os.path.basename(f)[:-6].split("-", 1)
    servers.append(s) if s not in servers else None
    clients.append(c) if c not in clients else None
    for line in open(f):
        r = json.loads(line)
        rows.setdefault((r["scenario"], r["name"]), {})[(s, c)] = r
names = {"go": "Go", "rust": "Rust", "js": "JS", "s1": "S1 rugregator", "s2": "S2 aggregator-go"}
cols = [(s, c) for s in servers for c in clients if any((s, c) in v for v in rows.values())]
print("| scenario | " + " | ".join(f"{names[s]} × {names[c]}" for s, c in cols) + " |")
print("|---|" + "---|" * len(cols))
tot = {}
for (scn, name), cells in sorted(rows.items(), key=lambda kv: (kv[0][0].rstrip("b"), kv[0][0])):
    out = []
    for col in cols:
        r = cells.get(col)
        out.append(r["status"] if r else "-")
        if r:
            tot[r["status"]] = tot.get(r["status"], 0) + 1
    print(f"| {scn} {name} | " + " | ".join(out) + " |")
print()
print("totals: " + ", ".join(f"{k}={v}" for k, v in sorted(tot.items())))
