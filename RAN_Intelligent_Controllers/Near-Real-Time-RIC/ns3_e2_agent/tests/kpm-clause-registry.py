"""kpm-clause-registry.py: load and check schema/kpm-measurement-clauses.v1.json, and parse map names against it.

Imported by lint-metric-map.py through importlib (the lint runs under python3 -I, so this directory is not on
sys.path). Nothing here reads the metric map; the lint applies these helpers row by row.
"""
import json
import re

INT32_MAX = 2**31 - 1
# the pinned documents: a gNB row is judged against 28.552 V20.2.0 only, an eNB row against 32.425 V19.0.0 only
PINS = {"28.552": "V20.2.0", "32.425": "V19.0.0", "28.552-v17": "V17.17.0", "kpm": "v03.00"}
DOC_FOR_KIND = {"gnb": "28.552", "enb": "32.425"}
LAYERS = ("PHY", "MAC", "RLC", "PDCP", "RRC")
# every field an entry needs, with the JSON type it must have (None in a tuple = JSON null)
ENTRY_FIELDS = {"name": str, "document": str, "version": str, "clause": str, "title": str, "pages": list,
                "objectClass": str, "rat": str, "layer": str, "unit": str, "dataType": str, "owningNode": list,
                "countingEvent": str, "splitOnly": bool, "dcExcluded": bool, "perUeAllowed": bool, "nameForms": dict,
                "v17Identical": (bool, type(None)), "legacyName": dict, "valueChecks": list}
# every field a value check needs; xform is the map transform the check judges the value after
CHECK_FIELDS = {"kind": str, "list": str, "src": str, "xform": str, "holds": bool, "source": list, "reason": str}
XFORMS = ("none", "ns_to_ms_floor")
SOURCE_REF = re.compile(r"^[\w.-]+@[0-9a-f]{7,40} \S+:\d+([-,]\d+)*$")


def clause_ref(entry):
    """The string a map row's `clause` field must carry for this entry."""
    title = {"28.552": "3GPP TS 28.552", "32.425": "3GPP TS 32.425"}[entry["document"]]
    return "%s %s §%s" % (title, entry["version"], entry["clause"])


def load(path):
    with open(path) as f:
        return json.load(f)


def _type_errs(tag, obj, fields):
    """Missing fields and fields of the wrong JSON type, in one finding each."""
    errs = []
    missing = [f for f in fields if f not in obj]
    if missing:
        errs.append("%s: missing %s" % (tag, missing))
    for f, t in fields.items():
        # bool is a subclass of int; no field here accepts an int, so isinstance is exact enough
        if f in obj and isinstance(obj[f], str) and str in (t if isinstance(t, tuple) else (t,)) and not _text(obj[f]):
            errs.append("%s: %s must not be blank" % (tag, f))
        elif f in obj and not isinstance(obj[f], t):
            errs.append("%s: %s must be %s" % (tag, f, " or ".join(
                "null" if x is type(None) else {str: "a string", bool: "true or false", list: "a list",
                                                dict: "an object"}[x] for x in (t if isinstance(t, tuple) else (t,)))))
    return errs


def _text(v):
    """A non-blank string: evidence and basis fields are read by truthiness elsewhere, so their type is pinned here."""
    return isinstance(v, str) and bool(v.strip())


def _str_list(v):
    return isinstance(v, list) and all(isinstance(x, str) for x in v)


def check_registry(reg):
    """Findings in the registry itself: wrong container or field types, missing fields, unpinned versions, malformed
    value checks. Every container and field is type-checked before it is read, so a malformed registry gives findings,
    never an exception; the lint skips the clause checks whenever this returns any finding."""
    if not isinstance(reg, dict):
        return ["registry: not a JSON object"]
    errs = []
    docs = reg.get("documents")
    if not isinstance(docs, dict):
        errs.append("registry: documents must be an object")
        docs = {}
    for d, ver in PINS.items():
        if not isinstance(docs.get(d), dict) or docs[d].get("version") != ver:
            errs.append("registry: document %s is not pinned to %s" % (d, ver))
    kinds = reg.get("slotKinds")
    if not isinstance(kinds, dict):
        errs.append("registry: slotKinds must be an object")
        kinds = {}
    for k, v in kinds.items():
        if k == "source":
            continue
        if not (isinstance(v, dict) and "label" in v and isinstance(v.get("pattern"), str)):
            errs.append("registry: slot kind %s needs label and a string pattern" % k)
            continue
        # null = a slot with no KPM label; otherwise the KPM v03.00 8.3.11 label text, which forbids the suffix
        if not (v["label"] is None or (isinstance(v["label"], str) and v["label"].strip())):
            errs.append("registry: slot kind %s label must be null or a non-empty string, not %r" % (k, v["label"]))
        try:
            re.compile(v["pattern"])
        except Exception as ex:  # noqa: BLE001 - re.compile also raises OverflowError, RecursionError, ...
            errs.append("registry: slot kind %s pattern does not compile: %s: %s" % (k, type(ex).__name__, ex))
    for key in ("families", "placeholders"):
        if not (isinstance(reg.get(key), dict) and isinstance(reg[key].get("names"), list) and
                all(_text(x) for x in reg[key]["names"])):
            errs.append("registry: %s must be an object whose names is a list of strings" % key)
    entries = reg.get("entries")
    if not isinstance(entries, list):
        return errs + ["registry: entries must be a list"]
    seen_entries = {}  # (document, name) -> first entry index: a name has one clause per document
    for i, e in enumerate(entries):
        if not isinstance(e, dict):
            errs.append("registry entry %d is not an object" % i)
            continue
        tag = "registry entry %d (%s)" % (i, e.get("name"))
        terrs = _type_errs(tag, e, ENTRY_FIELDS)
        if terrs:
            errs += terrs
            continue
        ident = (e["document"], e["name"])
        if ident in seen_entries:
            errs.append("%s: duplicate entry %s %s (also entry %d): a verdict must not depend on entry order" % (
                tag, ident[0], ident[1], seen_entries[ident]))
        seen_entries.setdefault(ident, i)
        if e["document"] not in DOC_FOR_KIND.values() or e["version"] != PINS[e["document"]]:
            errs.append("%s: %s %s is not a pinned judging document" % (tag, e["document"], e["version"]))
        if not e["pages"] or not all(isinstance(p, int) and not isinstance(p, bool) and p > 0 for p in e["pages"]):
            errs.append("%s: pages must be PDF page numbers" % tag)
        if e["layer"] not in LAYERS: errs.append("%s: bad layer %r" % (tag, e["layer"]))
        if e["dataType"] not in ("INTEGER", "REAL"): errs.append("%s: bad dataType" % tag)
        if not e["owningNode"] or not _str_list(e["owningNode"]) or set(e["owningNode"]) - set(DOC_FOR_KIND):
            errs.append("%s: bad owningNode" % tag)
        want_v17 = (bool,) if e["document"] == "28.552" else (type(None),)
        if not isinstance(e["v17Identical"], want_v17):
            errs.append("%s: v17Identical must be %s" % (tag, "a boolean" if e["document"] == "28.552" else "null"))
        if not isinstance(e["legacyName"].get("v17"), (str, type(None))):
            errs.append("%s: legacyName.v17 must be a string or null" % tag)
        nf = e["nameForms"]
        if not isinstance(nf.get("total"), bool) or not _text(nf.get("totalBasis")):
            errs.append("%s: nameForms needs total and totalBasis" % tag)
        templates = nf.get("templates", [])
        if not isinstance(templates, list) or not all(isinstance(t, list) for t in templates):
            errs.append("%s: nameForms.templates must be a list of lists" % tag)
        else:
            for t in templates:
                if not t or not _str_list(t) or any(k not in kinds or k == "source" for k in t):
                    errs.append("%s: template %r uses an unknown slot kind" % (tag, t))
        seen_checks = set()  # (kind, list, src): one check per map row source, so array order decides nothing
        for j, c in enumerate(e["valueChecks"]):
            if not isinstance(c, dict):
                errs.append("%s value check %d is not an object" % (tag, j))
                continue
            ctag = "%s value check %s/%s %s" % (tag, c.get("kind"), c.get("list"), c.get("src"))
            terrs = _type_errs(ctag, c, CHECK_FIELDS)
            if terrs:
                errs += terrs
                continue
            cid = (c["kind"], c["list"], c["src"])
            if cid in seen_checks:
                errs.append("%s: duplicate value check for %s/%s %s: a verdict must not depend on check order" % (
                    ctag, cid[0], cid[1], cid[2]))
            seen_checks.add(cid)
            if c["xform"] not in XFORMS: errs.append("%s: xform %r is not one of %s" % (ctag, c["xform"], XFORMS))
            if "gaps" in c and not isinstance(c["gaps"], list):
                errs.append("%s: gaps must be a list" % ctag)
            elif c["holds"] and "gaps" not in c:
                errs.append("%s: a value check that holds needs an explicit empty gaps list" % ctag)
            elif c["holds"] and c["gaps"]:
                errs.append("%s: a value check with gaps (paths that drop or add counted events) cannot hold" % ctag)
            if not c["source"] or not all(isinstance(x, str) and SOURCE_REF.fullmatch(x) for x in c["source"]):
                errs.append("%s: every source must be '<repo>@<sha> <file>:<line>'" % ctag)
            if c["holds"] and e["dataType"] == "INTEGER":
                mx = c.get("maxValue")
                if not isinstance(mx, int) or isinstance(mx, bool) or not _text(c.get("maxValueBasis")):
                    errs.append("%s: an INTEGER value check needs maxValue and maxValueBasis" % ctag)
    return errs


def match_entry(reg, doc, name):
    """(entry, suffix tokens) for the longest entry name of `doc` that `name` equals or extends with '.'."""
    best = None
    for e in reg.get("entries", []):
        if e.get("document") != doc: continue
        b = e["name"]
        if (name == b or name.startswith(b + ".")) and (best is None or len(b) > len(best["name"])):
            best = e
    if best is None:
        return None, []
    # no tokens only for the exact entry name; 'X.' gives [''], which suffix_findings reports
    return best, ([] if name == best["name"] else name[len(best["name"]) + 1:].split("."))


def entries_named(reg, name, doc):
    """The entries whose name `name` equals or extends with '.': those of `doc` when it has one, else those of any
    document (an NR-only name on an eNB row still meets the NR clause's split-only and DC exclusions)."""
    hits = [e for e in reg.get("entries", []) if name == e["name"] or name.startswith(e["name"] + ".")]
    own = [e for e in hits if e.get("document") == doc]
    return own or hits


def v17_successor(reg, name):
    """The V20.2.0 entry whose V17.17.0 name is `name` (a V17-only name), else None."""
    for e in reg.get("entries", []):
        if (e.get("legacyName") or {}).get("v17") == name:
            return e
    return None


def suffix_findings(reg, entry, tokens):
    """Name-grammar findings for a name = entry name + tokens: a suffix whose slot kind has a KPM label fails, and a
    bare name needs the clause's total form."""
    kinds = reg["slotKinds"]
    if "" in tokens:
        return ["name has an empty suffix component (a leading, trailing or doubled '.')"]
    if not tokens:
        return [] if entry["nameForms"]["total"] else [
            "bare name: the clause defines no total form (%s)" % entry["nameForms"]["totalBasis"]]
    for t in entry["nameForms"].get("templates", []):
        if len(t) == len(tokens) and all(re.fullmatch(kinds[k]["pattern"], tok) for k, tok in zip(t, tokens)):
            labelled = ["%s=%s (KPM label %s)" % (tok, k, kinds[k]["label"]) for k, tok in zip(t, tokens)
                        if kinds[k]["label"]]
            if labelled:
                return ["suffix encodes a sub-counter that KPM v03.00 8.3.11 carries as a Measurement Label: " +
                        ", ".join(labelled)]
            return []
    return ["suffix .%s is not in the clause's name grammar" % ".".join(tokens)]


def vendor_name_findings(reg, name):
    """An ns3.* name may not reuse a 3GPP family name or placeholder. Tokens are compared without
    case (the specs spell one placeholder QOS, QoS and Qos); a token that starts with a family followed by an upper-case
    letter or a digit (tbNbrDl, qosFlowVolume) also reuses it."""
    fams = {f.lower(): f for f in reg["families"]["names"]}
    ph = {p.lower(): p for p in reg["placeholders"]["names"]}
    errs = []
    for tok in name.split(".")[1:]:
        if not tok:
            errs.append("ns3 name has an empty component")
            continue
        low = tok.lower()
        if low in fams or low in ph:
            errs.append("ns3 name reuses the 3GPP %s %r" % ("family" if low in fams else "placeholder",
                                                           fams[low] if low in fams else ph[low]))
            continue
        glued = sorted((f for f in fams if low.startswith(f) and len(tok) > len(f) and
                        (tok[len(f)].isupper() or tok[len(f)].isdigit())), key=len, reverse=True)
        if glued:
            errs.append("ns3 name token %r starts with the 3GPP family %r" % (tok, fams[glued[0]]))
    return errs


def value_check(entry, kind, lst, src):
    for c in entry["valueChecks"]:
        if (c["kind"], c["list"], c["src"]) == (kind, lst, src):
            return c
    return None
