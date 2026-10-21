#!/usr/bin/env python3
"""lint-metric-map.py [metric-map.v1.json] [--samples trace.ndjson]

Lints the ns-3 -> E2SM-KPM metric map. Exit 0 = clean, 1 = findings.

Checks:
  - every row has the required fields with valid values;
  - one record type per KPM name across the whole map (an Influx field-type
    conflict makes kpimon's write fail silently);
  - names are PrintableString-legal (no '_') and 1..150 characters;
  - per (kind, list): order is 1..n, names are unique, measId = base + order
    (cell base 0, ue base 1000), so measIds are unique and stable;
  - both lists start with ns3.nodeId, ns3.simTimeMs, ns3.seq and the UE list
    has ns3.imsi at order 4;
  - no name overlaps the 9 names NIST's kpm_sim already writes
    (encode_kpm.cpp:30-40), which sit in cellMetrics since M3.
With --samples, also reports every src pointer that never resolves in any
sample line of the matching kind (hello lines give the kind). Pointers through
an array index (the neighbour slots, padded with noValue by design) are only
reported as INFO: scenario-zero has fewer than 8 neighbour cells.
"""
import json
import os
import re
import sys

KPM_SIM_NAMES = {
    "DRB.RlcSduTransmittedVolumeDL", "DRB.RlcSduTransmittedVolumeUL", "DRB.PerDataVolumeDLDist.Bin",
    "DRB.PerDataVolumeULDist.Bin", "DRB.RlcPacketDropRateDLDist", "DRB.PacketLossRateULDist",
    "L1M.DL-SS-RSRP.SSB", "L1M.DL-SS-SINR.SSB", "L1M.UL-SRS-RSRP",
}
PRINTABLE = re.compile(r"^[A-Za-z0-9 '()+,\-./:=?]{1,150}$")
FIELDS = ["kind", "list", "order", "measId", "kpm", "type", "scope", "src", "xform", "unit", "origin", "legacyName"]
LEAD = ["ns3.nodeId", "ns3.simTimeMs", "ns3.seq"]


def resolve(root, pointer):
    cur = root
    for tok in pointer[1:].split("/"):
        tok = tok.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, dict) and tok in cur:
            cur = cur[tok]
        elif isinstance(cur, list) and tok.isdigit() and int(tok) < len(cur):
            cur = cur[int(tok)]
        else:
            return False
    return True


def lint(doc):
    errs = []
    rows = doc.get("rows")
    if not isinstance(rows, list) or not rows:
        return ["no rows"]
    types = {}
    lists = {}
    for r in rows:
        missing = [f for f in FIELDS if f not in r]
        if missing:
            errs.append("row %r missing %s" % (r.get("kpm"), missing))
            continue
        tag = "%s/%s/%s" % (r["kind"], r["list"], r["kpm"])
        if r["kind"] not in ("gnb", "enb"): errs.append(tag + ": bad kind")
        if r["list"] not in ("cell", "ue"): errs.append(tag + ": bad list")
        if r["type"] not in ("INTEGER", "REAL"): errs.append(tag + ": bad type")
        if r["scope"] not in ("sample", "ue"): errs.append(tag + ": bad scope")
        if r["xform"] not in ("none", "ns_to_ms_floor"): errs.append(tag + ": bad xform")
        if not isinstance(r["src"], str) or not r["src"].startswith("/"): errs.append(tag + ": src not a JSON pointer")
        if r["list"] == "cell" and r["scope"] != "sample": errs.append(tag + ": cell rows must have sample scope")
        if not PRINTABLE.match(r["kpm"]): errs.append(tag + ": name not PrintableString-legal")
        if r["kpm"] in KPM_SIM_NAMES: errs.append(tag + ": overlaps a kpm_sim name")
        prev = types.setdefault(r["kpm"], r["type"])
        if prev != r["type"]: errs.append(tag + ": type %s conflicts with %s elsewhere" % (r["type"], prev))
        lists.setdefault((r["kind"], r["list"]), []).append(r)
    for (kind, lst), rs in sorted(lists.items()):
        base = 0 if lst == "cell" else 1000
        rs.sort(key=lambda r: r["order"])
        names = [r["kpm"] for r in rs]
        if [r["order"] for r in rs] != list(range(1, len(rs) + 1)):
            errs.append("%s/%s: order is not 1..n" % (kind, lst))
        for r in rs:
            if r["measId"] != base + r["order"]:
                errs.append("%s/%s/%s: measId %s != %d + order" % (kind, lst, r["kpm"], r["measId"], base))
        if len(set(names)) != len(names):
            errs.append("%s/%s: duplicate names" % (kind, lst))
        lead = LEAD + (["ns3.imsi"] if lst == "ue" else [])
        if names[:len(lead)] != lead:
            errs.append("%s/%s: must start with %s" % (kind, lst, lead))
    for kind in {k for k, _ in lists}:
        for lst in ("cell", "ue"):
            if (kind, lst) not in lists: errs.append("%s: list %s is empty" % (kind, lst))
        ids = [r["measId"] for (k, _), rs in lists.items() if k == kind for r in rs]
        if len(set(ids)) != len(ids): errs.append("%s: measIds not unique" % kind)
    return errs


def check_samples(doc, path):
    seen = {}
    kind = None
    with open(path) as f:
        for line in f:
            m = json.loads(line)
            if m.get("type") == "hello": kind = m.get("kind")
            if m.get("type") != "sample" or kind is None: continue
            for r in doc["rows"]:
                if r["kind"] != kind: continue
                key = (r["kind"], r["list"], r["kpm"])
                roots = [m] if r["scope"] == "sample" else m.get("ues", [])
                seen[key] = seen.get(key, False) or any(resolve(x, r["src"]) for x in roots)
    padded = {(r["kind"], r["list"], r["kpm"]) for r in doc["rows"] if any(t.isdigit() for t in r["src"].split("/"))}
    for k, ok in sorted(seen.items()):
        if not ok and k in padded:
            print("INFO padded slot never present: %s/%s/%s" % k)
    return ["src never resolves: %s/%s/%s" % k for k, ok in sorted(seen.items()) if not ok and k not in padded]


def main(argv):
    args = argv[1:]
    samples = None
    if "--samples" in args:
        i = args.index("--samples")
        samples = args[i + 1]
        del args[i:i + 2]
    path = args[0] if args else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "schema",
                                             "metric-map.v1.json")
    doc = json.load(open(path))
    errs = lint(doc)
    if samples: errs += check_samples(doc, samples)
    for e in errs: print("FAIL", e)
    n = {}
    for r in doc.get("rows", []): n["%s/%s" % (r.get("kind"), r.get("list"))] = n.get("%s/%s" % (r.get("kind"), r.get("list")), 0) + 1
    print(json.dumps({"map": os.path.basename(path), "rows": len(doc.get("rows", [])), "lists": n, "findings": len(errs)}))
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
