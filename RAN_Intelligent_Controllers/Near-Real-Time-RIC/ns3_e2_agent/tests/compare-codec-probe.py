#!/usr/bin/env python3
"""compare-codec-probe.py <probe-out-dir> <harness-ind.jsonl> <harness-ranfunc.jsonl>

R1 verdict: compares what codec-probe encoded (expect.json) with what kpimon's
own decoder library returned through tools/kpimon-decode-harness
(--records and --ranfunc). Pass = every piece is a clean RC_OK (code RC_OK,
consumed == length, header TimeStamp 8 octets), list lengths match the map,
and every record is identical, REAL values bit-for-bit. Exit 1 on any failure.
"""
import json
import sys


def main(argv):
    if len(argv) != 4:
        sys.exit(__doc__)
    exp = json.load(open(argv[1] + "/expect.json"))
    ind = {r["id"]: r for r in map(json.loads, open(argv[2]))}
    rf = [json.loads(l) for l in open(argv[3])][0]
    fails = []

    def check(ok, what):
        print(("  ok   " if ok else "  FAIL ") + what)
        if not ok:
            fails.append(what)

    cell, ue = exp["ranfunc"]["cell"], exp["ranfunc"]["ue"]
    s = rf["strict"]
    check(s["code"] == "RC_OK" and s["consumed"] == rf["len"], "ranfunc strict clean RC_OK (%s, %s/%s)" % (s["code"], s["consumed"], rf["len"]))
    check(s.get("shortName") == "ORAN-E2SM-KPM", "ranfunc shortName ORAN-E2SM-KPM")
    check(s.get("oid") == "1.3.6.1.4.1.53148.1.3.2.2", "ranfunc E2SM OID")
    check(s.get("description") == exp["ranfunc"]["description"], "ranfunc description " + exp["ranfunc"]["description"])
    check(s.get("instance") == 1 and s.get("eventTriggerStyles") == 1, "ranfunc instance 1, one event trigger style")
    st = s.get("styles", [])
    check([(x["type"], x["actFmt"], x["hdrFmt"], x["msgFmt"]) for x in st] == [(1, 1, 1, 1), (3, 3, 1, 2)],
          "ranfunc report styles {1: act1->msg1}, {3: act3->msg2}")
    if len(st) == 2:
        check(st[0]["names"] == cell and st[0]["ids"] == list(range(1, len(cell) + 1)), "style 1 = cell list (%d), measIDs 1..n" % len(cell))
        check(st[1]["names"] == ue and st[1]["ids"] == list(range(1001, 1001 + len(ue))), "style 3 = UE list (%d), measIDs 1001.." % len(ue))
    check(rf["kpimon"]["cell"] == cell, "kpimon buildRanCellUeKpi cell list == map (%d)" % len(rf["kpimon"]["cell"]))
    check(rf["kpimon"]["ue"] == ue, "kpimon buildRanCellUeKpi UE list == map (%d)" % len(rf["kpimon"]["ue"]))

    shapes = {"f1": (1, len(cell), None), "f2ueid": (2, 6, 2), "f2noueid": (2, 6, 0), "f2full": (2, 4 * len(ue), 4)}
    for name, (fmt, nrec, nue) in shapes.items():
        r = ind.get(name)
        if r is None:
            check(False, name + " missing from harness output")
            continue
        clean = (r["hdr_code"] == "RC_OK" and r["hdr_consumed"] == r["hdr_len"] and r["ts_len"] == 8 and
                 r["msg_code"] == "RC_OK" and r["msg_consumed"] == r["msg_len"])
        check(clean, "%s clean RC_OK: header %s %d/%d ts_len %s, message %s %d/%d" % (
            name, r["hdr_code"], r["hdr_consumed"], r["hdr_len"], r["ts_len"], r["msg_code"], r["msg_consumed"], r["msg_len"]))
        check(r.get("header", {}).get("ts_hex") == exp["header_ts_hex"], name + " header colletStartTime octets")
        check(r["msg_format"] == fmt and len(r.get("records", [])) == nrec, "%s format %d with %d records" % (name, fmt, nrec))
        check(r.get("records") == exp[name], name + " records identical (REAL bit-exact)")
        if nue is not None:
            check(r.get("ueIdsPerItem") == nue and r.get("ueIdsUniform"), "%s %d UE IDs per measCondUEid item" % (name, nue))
    check(ind.get("f2ueid", {}).get("amfUeNgapIds") == [2, 1099511627775], "f2ueid amf-UE-NGAP-IDs [2, 2^40-1]")
    check(ind.get("f2full", {}).get("condItems") == len(ue), "f2full one measCondUEid item per UE-list metric")
    reals = sum(1 for k in shapes for x in exp[k] if x["t"] == "real")
    print(json.dumps({"verdict": "PASS" if not fails else "FAIL", "failures": len(fails), "real_records_compared": reals,
                      "sizes": exp["sizes"]}))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
