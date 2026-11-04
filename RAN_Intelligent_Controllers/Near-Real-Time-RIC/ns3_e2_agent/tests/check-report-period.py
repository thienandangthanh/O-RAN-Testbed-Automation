#!/usr/bin/env python3
"""check-report-period.py <kpm-report-period-test out-dir>

Decodes what kpm-report-period-test wrote with an independent codec (pycrate,
the e2indep package of the asn1-indep image) and checks it:
  - P = 1000 ms, G = 100 ms: one cell Format 1 and the UE Format 2 messages,
    each with 10 measData items and granulPeriod 100; item t equals the records
    of the P = T message of sample t (a UE absent from a sample: noValue); the
    header is the first sample's; the RIC INDICATION carries the message;
  - P = 150 ms or an undecodable trigger: RIC SUBSCRIPTION FAILURE, Cause
    ricRequest eventTriggerNotSupported; G = 200 ms alone: the same with
    action-not-supported; mixed actions: a RESPONSE with 4 not admitted;
  - K = P / T = 20: a RESPONSE; K = 21 or P = 10000 ms: RIC SUBSCRIPTION
    FAILURE, Cause ricRequest function-resource-limit.
Run: podman run --rm --network=none -v <tests>:/t:ro -v <out>:/rp:ro \
       localhost/asn1-indep:<tag> python3 /t/check-report-period.py /rp
Exit 1 on any failure.
"""
import sys
from e2indep import e2ap, kpm
if len(sys.argv) != 2:
    sys.exit(__doc__)
rp = sys.argv[1]
hexf = lambda n: bytes.fromhex(open(f"{rp}/{n}.hex").read().strip())
ok = True
def check(c, what):
    global ok
    print("PASS" if c else "FAIL", what); ok = ok and c

lines = {}
for l in open(f"{rp}/ind-lines.txt"):
    k, h, m = l.split(); lines[k] = (bytes.fromhex(h), bytes.fromhex(m))

def recs(item):  # one measData item -> its record values
    return list(item["measRecord"])

# (b) cell: one Format 1 with 10 items; item t == T/T message of seq 26+t
h, m = lines["p1000-cell"]
d = kpm.decode_indication_message(m)
fmt, f1 = d["format"], d["raw"]
hd = kpm.decode_indication_header(h)
print("p1000 header:", hd)
print("p1000 cell: format", fmt, "granulPeriod", f1.get("granulPeriod"), "measData items", len(f1["measData"]))
check(fmt == "indicationMessage-Format1" and len(f1["measData"]) == 10 and f1.get("granulPeriod") == 100,
      "p1000 cell: Format 1, 10 measData items, granulPeriod 100")
tt = sorted([k for k in lines if k.startswith("tt-") and k.endswith("-cell")])
same = sum(recs(f1["measData"][t]) == recs(kpm.decode_indication_message(lines[k][1])["raw"]["measData"][0])
           for t, k in enumerate(tt))
check(same == 10, f"p1000 cell: item t == T/T record list of seq 26+t ({same}/10)")
check(h == lines[tt[0]][0], "p1000 header == seq 26's T/T header (colletStartTime of the first sample)")

# (b) UE: Format 2, 10 items, per (seq, UE) records == T/T
def ue_map(msg):
    d = kpm.decode_indication_message(msg); fmt, f2 = d["format"], d["raw"]
    # UE key: the en-gNB-UEID m-eNB-UE-X2AP-ID (the test's ueContext sets it to the IMSI);
    # any other UEID alternative keys as None and fails the comparison below.
    ues = [u["ueID"][1]["m-eNB-UE-X2AP-ID"] if u["ueID"][0] == "en-gNB-UEID" else None
           for u in f2["measCondUEidList"][0]["matchingUEidList"]]
    nm = len(f2["measCondUEidList"]); out = {}
    for t, it in enumerate(f2["measData"]):
        r = recs(it)
        for ui, ue in enumerate(ues):
            out[(t, ue)] = [r[k * len(ues) + ui] for k in range(nm)]
    return fmt, f2, out
want = {}
for t in range(10):
    for k in sorted(x for x in lines if x.startswith(f"tt-{26+t}-ue")):
        want.update({(t, ue): v for (_, ue), v in ue_map(lines[k][1])[2].items()})
got = {}; shapes = True
for k in sorted(x for x in lines if x.startswith("p1000-ue")):
    fmt, f2, mp = ue_map(lines[k][1]); got.update(mp)
    shapes &= fmt == "indicationMessage-Format2" and len(f2["measData"]) == 10 and f2.get("granulPeriod") == 100
check(shapes, "p1000 UE: Format 2, 10 measData items, granulPeriod 100 in every UE message")
match = sum(got.get(k) == v for k, v in want.items())
absent = [k for k in got if k not in want]
check(match == len(want) and all(all(r[0] == "noValue" for r in got[k]) for k in absent),
      f"p1000 UE: {match}/{len(want)} (seq, UE) record lists equal T/T; {len(absent)} absent pairs all noValue")

# (b) E2AP indication wraps it
ind = e2ap.decode_e2ap(hexf("e2ap-p1000-indication-cell"))
check(ind["message"] == "RICindication" and ind["ies"]["id-RICindicationMessage"] == m,
      "p1000: E2AP RICindication decodes, carries the 10-item message")
for n in ("p1000-request", "p150-request", "g200-request"):
    r = e2ap.decode_e2ap(hexf(f"e2ap-{n}"))
    det = r["ies"]["id-RICsubscriptionDetails"]
    print(n, "eventTrigger", det["ricEventTriggerDefinition"].hex(),
          "actions", [(a["value"][1]["ricActionID"], a["value"][1]["ricActionType"], len(a["value"][1].get("ricActionDefinition", b"")))
                      for a in det["ricAction-ToBeSetup-List"]])
for n, cause in (("p100", None), ("p1000", None), ("p150", "eventTriggerNotSupported"), ("badtrigger", "eventTriggerNotSupported"),
                 ("g200", "action-not-supported"), ("mixed", None), ("k20", None),
                 ("k21", "function-resource-limit"), ("p10000", "function-resource-limit")):
    a = e2ap.decode_e2ap(hexf(f"e2ap-{n}-answer"))
    print(n, "answer:", a["kind"], a["message"], {k: v for k, v in a["ies"].items()})
    if cause:
        check(a["kind"] == "unsuccessfulOutcome" and a["message"] == "RICsubscriptionFailure" and a["ies"]["id-Cause"] == ("ricRequest", cause),
              f"{n}: RICsubscriptionFailure, Cause ricRequest {cause}")
    else:
        check(a["kind"] == "successfulOutcome" and a["message"] == "RICsubscriptionResponse", f"{n}: RICsubscriptionResponse")
mixed = e2ap.decode_e2ap(hexf("e2ap-mixed-answer"))["ies"]
check(str(mixed.get("id-RICactions-NotAdmitted", "")).count("action-not-supported") == 4, "mixed: 4 not admitted, action-not-supported")
print("check-report-period:", "ok" if ok else "FAILED"); sys.exit(0 if ok else 1)
