#!/usr/bin/env python3
"""lint-metric-map.py [metric-map.v1.json] [--registry clauses.json] [--samples trace.ndjson]
                      [--kpimon-enb enb-kpm-measurements.json] | --self-test

Lints the ns-3 -> E2SM-KPM metric map. Exit 0 = clean, 1 = findings.

The map object, its rows list, each row object, the required row fields and their JSON types are checked first; any
finding there skips every other check, --kpimon-enb and --samples included (exit 1), because they all traverse the
rows.
Structural checks:
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
Clause checks against schema/kpm-measurement-clauses.v1.json (the registry). The registry's own containers, fields
and field types are checked first, and no two entries share (document, name) and no entry has two value checks
for one (kind, list, src), so no verdict depends on array order; if that finds anything, the findings are reported
and the clause checks below are skipped (exit 1), because they read the registry's fields.
  (1) every row carries `clause` and `layer` as non-empty strings;
  (2) a non-ns3. name names a registry entry of its node's document (gnb: 3GPP TS 28.552 V20.2.0, enb: 3GPP TS
      32.425 V19.0.0, exact versions) and its `clause` is that entry's;
  (3) the row's unit, type and layer equal the entry's; its src section fits the layer (du: PHY/MAC/RLC, cuUp:
      PDCP, cuCp: RRC); its node owns the counted event; a value check for (kind, list, src) exists, judges the
      value after the row's xform (the check's `xform` equals the row's), and holds: ns-3
      counts the clause's events exactly once on every path the runs reach, only the counting instant may shift (by
      at most 1 slot for a count, 1 of the clause's own sampling steps for a sampled value; the E2 report period is
      never a sampling step), and the check carries an explicit empty `gaps` list (a check that lists gaps, paths
      the runs reach that drop or add counted events, cannot hold);
      a split-only or DC-excluded entry (of the row's document, or of any document when that has no entry of the
      name) fails on every node (the en-gNB is non-split, every bearer is DC); a UE row
      needs perUeAllowed (KPM v03.00 7.9);
  (4) the name parses against the clause's name grammar; a suffix with a KPM 8.3.11 label fails; an empty suffix
      component (a trailing or doubled '.') fails; only the exact entry name is the bare name, and it needs the
      clause's total form;
  (5) an INTEGER value check carries a bound inside kpimon's int32;
  (6) an ns3.* row has clause "vendor"; its layer is "none" exactly when it is an identity row (the LEAD names, and
      ns3.imsi in the UE list); any other layer fits its src section as in (3), except the named rows of
      VENDOR_LAYER_EXCEPTIONS that ns-3 reports outside their layer's section; no name token is a 3GPP
      family or placeholder, compared without case, nor starts with a family followed by an upper-case letter or
      a digit;
  (7) a V17-only name fails (2) and names its V20.2.0 successor; a row moved to the successor passes only through
      the successor's own entry and value check;
  (8) a row that carries a pendingFix field is a finding: no row's finding is waived, every row passes or fails on
      its own checks.
With --kpimon-enb, also requires kpimon's eNB measurement lists
(install_patch_files/xApps/kpimon-go/control/enb-kpm-measurements.json: e2mgr stores no RAN
functions for an eNB, so kpimon takes them from that file) to equal this map's kind-enb rows:
"cell" and "ue" = [(measName = kpm, measId)] in order, and no other key than doc, cell, ue.
With --samples, also reports every src pointer that never resolves in any
sample line of the matching kind (hello lines give the kind). Pointers through
an array index (the neighbour slots, padded with noValue by design) are only
reported as INFO: scenario-zero has fewer than 8 neighbour cells.
"""
import importlib.util
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.dont_write_bytecode = True  # the sibling modules load through importlib; leave no bytecode cache in the tree


def _load(name, file):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, file))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


reg_mod = _load("kpm_clause_registry", "kpm-clause-registry.py")
DEFAULT_REGISTRY = os.path.join(HERE, "..", "schema", "kpm-measurement-clauses.v1.json")

KPM_SIM_NAMES = {
    "DRB.RlcSduTransmittedVolumeDL", "DRB.RlcSduTransmittedVolumeUL", "DRB.PerDataVolumeDLDist.Bin",
    "DRB.PerDataVolumeULDist.Bin", "DRB.RlcPacketDropRateDLDist", "DRB.PacketLossRateULDist",
    "L1M.DL-SS-RSRP.SSB", "L1M.DL-SS-SINR.SSB", "L1M.UL-SRS-RSRP",
}
PRINTABLE = re.compile(r"^[A-Za-z0-9 '()+,\-./:=?]{1,150}$")
FIELDS = ["kind", "list", "order", "measId", "kpm", "type", "scope", "src", "xform", "unit", "origin", "legacyName"]
LEAD = ["ns3.nodeId", "ns3.simTimeMs", "ns3.seq"]
SECTION_LAYERS = {"du": ("PHY", "MAC", "RLC"), "cuUp": ("PDCP",), "cuCp": ("RRC",)}
# the map's identity rows (doc header: both lists start with LEAD, ns3.imsi is UE item 4): the only rows with layer none
IDENTITY = {"cell": set(LEAD), "ue": set(LEAD) | {"ns3.imsi"}}
# ns3.* rows whose quantity ns-3 reports outside its layer's section, by (section, layer), at ns-3-mmwave-oran@74c165f1:
# the CU-UP reports carry the TX counters of the UE's RLC entities (mmwave-enb-net-device.cc:711-726, NR RLC;
# lte-enb-net-device.cc:1124-1134, LTE RLC); the en-gNB DU report carries the size of the RRC UE map
# (mmwave-enb-net-device.cc:1372). Every other ns3.* row must fit SECTION_LAYERS like a 3GPP row.
VENDOR_LAYER_EXCEPTIONS = {
    ("cuUp", "RLC"): {"ns3.cuUp.txPdcpPduBytesNrRlc", "ns3.cuUp.txPdcpPduNrRlc", "ns3.cuUp.txPdcpPduLteRlc",
                      "ns3.cuUp.txPdcpPduBytesLteRlc"},
    ("du", "RRC"): {"ns3.du.numActiveUes"},
}


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
        if not PRINTABLE.fullmatch(r["kpm"]): errs.append(tag + ": name not PrintableString-legal")
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


def section(src):
    parts = src.split("/")
    return parts[2] if len(parts) > 2 and parts[1] == "cell" else (parts[1] if len(parts) > 1 else "")


def row_findings(reg, r):
    """[(conjunct, message)] of one row under the clause checks (1)-(6) of the module docstring."""
    out = []
    name, kind, lst = r.get("kpm", ""), r.get("kind"), r.get("list")
    for f in ("clause", "layer"):
        if not (isinstance(r.get(f), str) and r[f]): out.append(("(1) fields", "row carries no %s" % f))
    if not isinstance(name, str):
        return out + [("(1) fields", "kpm %r is not a string" % (name,))]
    if name.startswith("ns3."):
        if r.get("clause") != "vendor": out.append(("(6) vendor", "an ns3.* row's clause must be 'vendor'"))
        layer, sec = r.get("layer"), section(r.get("src") if isinstance(r.get("src"), str) else "")
        if name in IDENTITY.get(lst, ()):
            if layer != "none": out.append(("(6) vendor", "identity row: layer %r must be 'none'" % (layer,)))
        elif layer == "none":
            out.append(("(1) fields", "layer 'none' is for the identity rows only (%s)" % ", ".join(
                sorted(IDENTITY["ue"]))))
        elif layer not in reg_mod.LAYERS:
            out.append(("(6) vendor", "bad layer %r" % (layer,)))
        elif layer not in SECTION_LAYERS.get(sec, ()) and name not in VENDOR_LAYER_EXCEPTIONS.get((sec, layer), ()):
            out.append(("(6) vendor", "src section %r does not fit layer %s" % (sec, layer)))
        out += [("(6) vendor", m) for m in reg_mod.vendor_name_findings(reg, name)]
        return out
    if r.get("layer") == "none": out.append(("(1) fields", "layer 'none' is for the ns3.* identity rows only"))
    doc = reg_mod.DOC_FOR_KIND.get(kind)
    for e in reg_mod.entries_named(reg, name, doc):
        if e["splitOnly"]: out.append(("(3) node", "%s is split-gNB only (%s); no node here is split" % (
            e["name"], e.get("splitOnlySource", reg_mod.clause_ref(e)))))
        if e["dcExcluded"]: out.append(("(3) node", "%s excludes dual connectivity (%s); every bearer here is DC" % (
            e["name"], e.get("dcExcludedSource", reg_mod.clause_ref(e)))))
    entry, tokens = reg_mod.match_entry(reg, doc, name)
    if entry is None:
        succ = reg_mod.v17_successor(reg, name)
        hint = "; V17-only name, its V20.2.0 successor is %s (successor rule)" % succ["name"] if succ else ""
        return out + [("(2) registry", "no registry entry in %s %s%s" % (doc, reg_mod.PINS.get(doc), hint))]
    if r.get("clause") != reg_mod.clause_ref(entry):
        out.append(("(2) registry", "clause %r != %r" % (r.get("clause"), reg_mod.clause_ref(entry))))
    out += [("(4) grammar", m) for m in reg_mod.suffix_findings(reg, entry, tokens)]
    if r.get("unit") != entry["unit"]: out.append(("(3) unit", "unit %r != %r" % (r.get("unit"), entry["unit"])))
    if r.get("type") != entry["dataType"]:
        out.append(("(3) type", "type %s != the clause's %s" % (r.get("type"), entry["dataType"])))
    if r.get("layer") != entry["layer"]:
        out.append(("(3) layer", "layer %s != %s" % (r.get("layer"), entry["layer"])))
    sec = section(r.get("src") if isinstance(r.get("src"), str) else "")
    if entry["layer"] not in SECTION_LAYERS.get(sec, ()):
        out.append(("(3) layer", "src section %r does not fit layer %s" % (sec, entry["layer"])))
    if kind not in entry["owningNode"]:
        out.append(("(3) node", "node kind %s does not own the counted event (owningNode %s)" % (
            kind, entry["owningNode"])))
    if lst == "ue" and not entry["perUeAllowed"]:
        out.append(("(3) per-UE", "perUeAllowed is false: %s" % entry.get("perUeSource", "KPM v03.00 7.9")))
    c = reg_mod.value_check(entry, kind, lst, r.get("src"))
    if c is not None and r.get("xform") != c["xform"]:
        out.append(("(3) xform", "xform %r != the value check's %r (the check judges the value after its xform)" % (
            r.get("xform"), c["xform"])))
    if c is None:
        out.append(("(3) value check", "no value check for %s/%s %s" % (kind, lst, r.get("src"))))
    elif not c["holds"]:
        out.append(("value check", "value check fails: %s" % c["reason"]))
    elif c.get("gaps") != []:
        out.append(("value check", "value check holds without an explicit empty gaps list: %r" % c.get("gaps")))
    elif entry["dataType"] == "INTEGER" and not (isinstance(c.get("maxValue"), int) and
                                                 not isinstance(c["maxValue"], bool) and
                                                 0 <= c["maxValue"] <= reg_mod.INT32_MAX):
        # a 3GPP INTEGER count is nonnegative and kpimon stores it in an int32
        out.append(("(5) int32", "maxValue %r is outside kpimon's int32 range [0, %d]" % (c.get("maxValue"),
                                                                                       reg_mod.INT32_MAX)))
    return out


def strict(doc, reg):
    """(findings, failing row tags) of the clause checks."""
    errs, failing = [], []
    for r in doc.get("rows", []):
        tag = "%s/%s/%s/%s" % (r.get("kind"), r.get("list"), r.get("order"), r.get("kpm"))
        got = row_findings(reg, r)
        if "pendingFix" in r:
            got.append(("(8) pending", "pendingFix %r: no finding is waived, the row passes or fails on its own "
                                       "checks" % (r["pendingFix"],)))
        if got:
            failing.append(tag)
            errs += ["%s: %s: %s" % (tag, c, m) for c, m in got]
    return errs, failing


# the JSON type of every row field the checks read (None in a tuple = JSON null); a missing field is lint()'s finding
ROW_TYPES = {"kind": str, "list": str, "order": int, "measId": int, "kpm": str, "type": str, "scope": str, "src": str,
             "xform": str, "unit": str, "origin": str, "legacyName": (str, type(None))}


def map_findings(doc):
    """Findings in the map's containers, required row fields and row field types. Every check traverses these
    (structural, clause, --kpimon-enb, --samples), so when this finds anything they are all skipped instead of
    raising."""
    if not isinstance(doc, dict):
        return ["map: not a JSON object"]
    rows = doc.get("rows")
    if not isinstance(rows, list):
        return ["map: rows must be a list"]
    errs = []
    for i, r in enumerate(rows):
        if not isinstance(r, dict):
            errs.append("map: row %d is not an object" % i)
            continue
        missing = [f for f in FIELDS if f not in r]
        if missing:
            errs.append("map: row %d (%r) missing %s" % (i, r.get("kpm"), missing))
        for f, t in ROW_TYPES.items():
            v = r.get(f)
            # bool is an int subclass; order and measId must be real integers
            if f in r and (not isinstance(v, t) or (t is int and isinstance(v, bool))):
                errs.append("map: row %d (%r): %s has the wrong JSON type %s" % (i, r.get("kpm"), f, type(v).__name__))
    return errs


def evaluate(doc, reg):
    """(findings, failing row tags) of the map, structural, registry and clause checks. The structural and
    clause checks traverse the map, so they run only when its containers and row types are sound; the clause checks
    read the registry's fields, so they run only when the registry check finds nothing."""
    map_errs = map_findings(doc)
    reg_errs = reg_mod.check_registry(reg)
    if map_errs:
        return map_errs + reg_errs + ["map has findings: structural and clause checks skipped"], []
    if reg_errs:
        return lint(doc) + reg_errs + ["registry has findings: clause checks skipped"], []
    serrs, failing = strict(doc, reg)
    return lint(doc) + serrs, failing


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


def check_kpimon_enb(doc, path):
    """kpimon's eNB lists == the map's kind-enb rows per list, in order."""
    cfg = json.load(open(path))
    errs = []
    if set(cfg) != {"doc", "cell", "ue"}:
        errs.append(f"{os.path.basename(path)}: keys {sorted(cfg)}, want doc, cell, ue")
    for name in ("cell", "ue"):
        want = [{"measName": r["kpm"], "measId": r["measId"]}
                for r in sorted((r for r in doc.get("rows", []) if r.get("kind") == "enb" and r.get("list") == name),
                                key=lambda r: r["order"])]
        if cfg.get(name) != want:
            errs.append(f"{os.path.basename(path)}: list {name} differs from the map's enb/{name} rows")
    return errs


def take(args, flag, has_value=True):
    if flag not in args: return None
    i = args.index(flag)
    v = args[i + 1] if has_value else True
    del args[i:i + (2 if has_value else 1)]
    return v


def main(argv):
    args = argv[1:]
    if take(args, "--self-test", False):
        return _load("lint_metric_map_selftest", "lint-metric-map-selftest.py").run(sys.modules[__name__])
    samples, kpimon_enb = take(args, "--samples"), take(args, "--kpimon-enb")
    reg_path = take(args, "--registry") or DEFAULT_REGISTRY
    path = args[0] if args else os.path.join(HERE, "..", "schema", "metric-map.v1.json")
    try:
        doc = json.load(open(path))
        reg = reg_mod.load(reg_path)
    except (OSError, ValueError) as ex:
        print("FAIL cannot read the map or the registry: %s" % ex)
        return 1
    errs, failing = evaluate(doc, reg)
    sound = not map_findings(doc)  # the extra checks and the summary traverse the rows too
    if sound and samples: errs += check_samples(doc, samples)
    if sound and kpimon_enb: errs += check_kpimon_enb(doc, kpimon_enb)
    for e in errs: print("FAIL", e)
    rows = doc["rows"] if sound else []
    n = {}
    for r in rows:
        key = "%s/%s" % (r.get("kind"), r.get("list"))
        n[key] = n.get(key, 0) + 1
    print(json.dumps({"map": os.path.basename(path), "registry": os.path.basename(reg_path),
                      "rows": len(rows), "lists": n, "findings": len(errs),
                      "rowsFailingClauseChecks": len(failing)}))
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
