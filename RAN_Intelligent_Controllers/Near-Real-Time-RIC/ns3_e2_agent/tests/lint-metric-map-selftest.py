"""lint-metric-map-selftest.py: the fixtures of `lint-metric-map.py --self-test`.

Each fixture copies the shipped map and the shipped registry, changes one thing and names the finding it must
produce; the shipped pair itself must pass with no finding. A fixture passes only when its expected finding text
appears, so a fixture that fails for another reason is caught; a fixture that expects a row to pass requires no finding
on that row. Any exception the lint raises fails the fixture: a malformed map or registry must give findings, never a
traceback.

The fixtures that change an eNB 3GPP row start from a control: the eNB mean-RRC-UE row put back under RRC.ConnMean
with its registry check marked as holding. The control row itself must pass, which shows that each such fixture fails
through its own change only.
"""
import contextlib
import copy
import io
import json
import os
import tempfile

C552 = "3GPP TS 28.552 V20.2.0 §"


def run(lint):
    here = os.path.dirname(os.path.abspath(lint.__file__))
    base_doc = json.load(open(os.path.join(here, "..", "schema", "metric-map.v1.json")))
    base_reg = json.load(open(lint.DEFAULT_REGISTRY))

    def evaluate(doc, reg):
        errs, _ = lint.evaluate(doc, reg)
        return errs

    def row_errs(errs, tag):
        """The findings on the row whose tag (kind/list/order/name) is tag."""
        return [e for e in errs if e.startswith(tag + ":")]

    def reg_set(key, value):
        return lambda doc, reg: reg.update({key: value})

    def entry_at(i, **kv):
        return lambda doc, reg: reg["entries"][i].update(kv)

    def row(doc, kind, lst, kpm):
        for r in doc["rows"]:
            if (r["kind"], r["list"], r["kpm"]) == (kind, lst, kpm):
                return r
        raise KeyError("fixture anchor %s/%s/%s is not in the shipped map" % (kind, lst, kpm))

    def entry(reg, doc_id, name):
        return next(e for e in reg["entries"] if (e["document"], e["name"]) == (doc_id, name))

    def as_3gpp(kind, lst, kpm, new, clause, layer, unit, typ):
        def f(doc, reg):
            row(doc, kind, lst, kpm).update(kpm=new, clause=clause, layer=layer, unit=unit, type=typ)
        return f

    def set_row(kind, lst, anchor, **kv):
        return lambda doc, reg: row(doc, kind, lst, anchor).update(kv)

    def drop_row_field(kind, lst, anchor, field):
        return lambda doc, reg: row(doc, kind, lst, anchor).pop(field)

    def reg_check(doc_id, name, **kv):
        return lambda doc, reg: entry(reg, doc_id, name)["valueChecks"][0].update(kv)

    def drop_check_field(doc_id, name, field):
        return lambda doc, reg: entry(reg, doc_id, name)["valueChecks"][0].pop(field, None)

    C425 = "3GPP TS 32.425 V19.0.0 §"
    conn = "ns3.cuCp.meanRrcUes"

    def passing_control(doc, reg):
        """The eNB mean-RRC-UE row under RRC.ConnMean, its 32.425 check marked as holding with no gaps."""
        row(doc, "enb", "cell", conn).update(kpm="RRC.ConnMean", clause=C425 + "4.1.3.1", layer="RRC", unit="count",
                                            type="INTEGER")
        entry(reg, "32.425", "RRC.ConnMean")["valueChecks"][0].update(holds=True, gaps=[])

    held = dict(holds=True, gaps=[], maxValue=10**7, maxValueBasis="fixture")

    def dup_check(doc_id, name, first, **kv):
        """A second check for the same (kind, list, src) as the entry's first, put before or after it."""
        def f(doc, reg):
            checks = entry(reg, doc_id, name)["valueChecks"]
            c = dict(checks[0], **kv)
            checks.insert(0, c) if first else checks.append(c)
        return f

    def shared_src(ue_first):
        """The control's cell row and an eNB UE row read one src; each list has its own failing check, the UE
        list's first or last. Each row must be judged by its own list's check whatever the order."""
        def f(doc, reg):
            passing_control(doc, reg)
            row(doc, "enb", "ue", "ns3.cuUp.txDlPackets").update(
                kpm="RRC.ConnMean", clause=C425 + "4.1.3.1", layer="RRC", unit="count", type="INTEGER",
                src="/cell/cuCp/meanRrcUes")
            checks = entry(reg, "32.425", "RRC.ConnMean")["valueChecks"]
            checks[0].update(holds=False, reason="cell-list check")
            ue = dict(checks[0], list="ue", reason="ue-list check")
            checks.insert(0, ue) if ue_first else checks.append(ue)
        return f

    def check_in_other_document(doc, reg):
        """The en-gNB DL row's own entry loses its check; a holding check for the same kind, list and src sits in
        the 32.425 entry of a near-identical name. It must not be found."""
        entry(reg, "28.552", "DRB.PdcpSduVolumeDL")["valueChecks"] = []
        other = entry(reg, "32.425", "DRB.PdcpSduVolumeDl")["valueChecks"]
        other.append(dict(other[0], kind="gnb", list="cell", src="/cell/cuUp/DRB.PdcpSduVolumeDL", **held))

    def decoy(where, own_holds, decoy_holds):
        """The en-gNB DL row's own check gets holds=own_holds; a decoy check for the same src with
        holds=decoy_holds sits before it, in the UE list of its own entry or in the cell list of an earlier 32.425
        entry. Only the row's own check (same document, kind, list and src) may decide the row's verdict."""
        def f(doc, reg):
            own = entry(reg, "28.552", "DRB.PdcpSduVolumeDL")["valueChecks"]
            own[0].update(dict(held if own_holds else {}, holds=own_holds))
            bad = dict(own[0], **dict(held if decoy_holds else {}, holds=decoy_holds), reason="decoy check")
            if where == "list":
                own.insert(0, dict(bad, list="ue"))
            else:
                entry(reg, "32.425", "DRB.PdcpSduVolumeDl")["valueChecks"].insert(0, bad)
        return f

    def on_control(*mutations):
        def f(doc, reg):
            passing_control(doc, reg)
            for m in mutations:
                m(doc, reg)
        return f

    PASS = "pass"
    qos = C552 + "5.1.3.6.1.1"
    nr_rlc = "ns3.cuUp.txPdcpPduBytesNrRlc"
    fixtures = [
        # (name, mutation, expected finding text or (PASS, tag of a row that must have no finding))
        ("mac-src-under-QosFlow.PdcpPduVolumeDL",
         as_3gpp("gnb", "cell", "ns3.du.macVolume", "QosFlow.PdcpPduVolumeDL", qos, "PDCP", "Kbit", "INTEGER"),
         "src section 'du' does not fit layer PDCP"),
        ("real-DRB.PdcpSduVolumeDL", set_row("gnb", "cell", "DRB.PdcpSduVolumeDL", type="REAL"),
         "type REAL != the clause's INTEGER"),
        ("mbit-unit", set_row("gnb", "cell", "DRB.PdcpSduVolumeDL", unit="Mbit"), "unit 'Mbit' != 'Kbit'"),
        ("mbit-unit-on-DRB.PdcpSduVolumeX2UL", set_row("gnb", "cell", "DRB.PdcpSduVolumeX2UL", unit="Mbit"),
         "gnb/cell/36/DRB.PdcpSduVolumeX2UL: (3) unit: unit 'Mbit' != 'Kbit'"),
        ("mbit-unit-on-DRB.PdcpSduVolumeX2DL", set_row("gnb", "cell", "DRB.PdcpSduVolumeX2DL", unit="Mbit"),
         "gnb/cell/37/DRB.PdcpSduVolumeX2DL: (3) unit: unit 'Mbit' != 'Kbit'"),
        ("split-only-name-on-gnb",
         as_3gpp("gnb", "ue", nr_rlc, "QosFlow.PdcpPduVolumeDL", qos, "PDCP", "Kbit", "INTEGER"),
         "is split-gNB only"),
        ("dc-excluded-name-on-gnb",
         as_3gpp("gnb", "ue", nr_rlc, "QosFlow.PdcpPduVolumeDL", qos, "PDCP", "Kbit", "INTEGER"),
         "excludes dual connectivity"),
        ("dc-excluded-name-on-enb",
         as_3gpp("enb", "ue", nr_rlc, "QosFlow.PdcpPduVolumeDL", qos, "PDCP", "Kbit", "INTEGER"),
         "excludes dual connectivity"),
        ("3gpp-name-without-registry-entry",
         as_3gpp("enb", "ue", "ns3.cuUp.txDlPackets", "Tot.PdcpSduNbrDl", C425 + "4.4.7.1", "PDCP", "count", "REAL"),
         "no registry entry in 32.425 V19.0.0"),
        ("5QI-suffix-on-a-name-without-total-form",
         as_3gpp("gnb", "ue", "ns3.cuCp.numDrb", "DRB.EstabSucc.5QI", C552 + "5.1.1.10.2", "RRC", "count", "INTEGER"),
         "Measurement Label: 5QI=fiveQi"),
        ("bare-name-without-total-form",
         as_3gpp("gnb", "ue", "ns3.cuCp.numDrb", "DRB.EstabSucc", C552 + "5.1.1.10.2", "RRC", "count", "INTEGER"),
         "the clause defines no total form"),
        ("mimo-layer-suffix",
         as_3gpp("gnb", "cell", "ns3.du.macPdu", "TB.TotNbrDl.1", C552 + "5.1.1.7.3", "MAC", "count", "INTEGER"),
         "1=muMimoLayer (KPM label Layer at MU-MIMO)"),
        ("TB.TotNbrDl-on-a-UE-row",
         as_3gpp("gnb", "ue", "ns3.du.macPdu", "TB.TotNbrDl", C552 + "5.1.1.7.3", "MAC", "count", "INTEGER"),
         "perUeAllowed is false"),
        ("TB.TotNbrDl-bare-name-not-in-item-e",
         as_3gpp("gnb", "cell", "ns3.du.macPdu", "TB.TotNbrDl", C552 + "5.1.1.7.3", "MAC", "count", "INTEGER"),
         "bare name: the clause defines no total form"),
        ("TB-count-that-drops-TBs-at-SN-change",
         as_3gpp("gnb", "cell", "ns3.du.macPduInitial", "TB.TotNbrDlInitial", C552 + "5.1.1.7.1", "MAC", "count",
                 "INTEGER"),
         "value check fails: The value is the sum over the en-gNB's UE map"),
        ("enb-RRC.ConnMean-under-its-3GPP-name",
         as_3gpp("enb", "cell", conn, "RRC.ConnMean", C425 + "4.1.3.1", "RRC", "count", "INTEGER"),
         "value check fails: Attach bound not yet proven by a run"),
        ("holds-true-without-a-gaps-key",
         on_control(drop_check_field("32.425", "RRC.ConnMean", "gaps")),
         "a value check that holds needs an explicit empty gaps list"),
        ("holds-true-with-gaps", on_control(reg_check("32.425", "RRC.ConnMean", gaps=["fixture path"])),
         "a value check with gaps"),
        ("enb-PDCP-PDU-kbit-under-DRB.PdcpSduVolumeDl",
         as_3gpp("enb", "ue", "ns3.cuUp.pdcpTxVolumeDl", "DRB.PdcpSduVolumeDl", C425 + "4.4.7.1", "PDCP", "Kbit",
                 "INTEGER"),
         "value check fails: The value is the UE's PDCP PDU kbit of the period"),
        ("enb-PDCP-PDU-rate-under-DRB.PdcpSduBitrateDl",
         as_3gpp("enb", "ue", "ns3.cuUp.pdcpThroughput", "DRB.PdcpSduBitrateDl", C425 + "4.4.1.1", "PDCP", "kbit/s",
                 "INTEGER"),
         "value check fails: The value is the UE's PDCP PDU kbit of the period (the DRB.PdcpSduVolumeDl value"),
        ("enb-0.1ms-cell-delay-under-DRB.PdcpSduDelayDl",
         as_3gpp("enb", "cell", "ns3.cuUp.cellAverageLatency", "DRB.PdcpSduDelayDl", C425 + "4.4.3.1", "PDCP", "ms",
                 "INTEGER"),
         "value check fails: The value is the unweighted mean"),
        ("enb-QCI-suffix-on-DRB.PdcpSduDelayDl",
         as_3gpp("enb", "ue", "ns3.cuUp.pdcpLatency", "DRB.PdcpSduDelayDl.9", C425 + "4.4.3.1", "PDCP", "ms",
                 "INTEGER"),
         "9=qci (KPM label QCI)"),
        ("gnb-RRC.ConnMean-in-EN-DC",
         as_3gpp("gnb", "cell", "ns3.cuCp.meanRrcUes", "RRC.ConnMean", C552 + "5.1.1.4.1", "RRC", "count", "INTEGER"),
         "RRC.ConnMean excludes dual connectivity"),
        ("ns3-name-with-a-3GPP-family", set_row("gnb", "ue", "ns3.du.macVolume", kpm="ns3.du.QosFlow.PdcpPduVolumeDL"),
         "reuses the 3GPP family 'QosFlow'"),
        ("ns3-name-glued-to-a-3GPP-family", set_row("gnb", "ue", "ns3.du.macVolume", kpm="ns3.du.QosFlowPdcpVolume"),
         "starts with the 3GPP family 'QosFlow'"),
        ("ns3-name-with-a-placeholder", set_row("gnb", "ue", "ns3.du.rlcBufferOccup", kpm="ns3.du.bufferSize.Qos"),
         "reuses the 3GPP placeholder 'Qos'"),
        ("ns3-name-with-a-lower-case-family", set_row("gnb", "ue", "ns3.du.macVolume", kpm="ns3.du.qosFlow.volume"),
         "reuses the 3GPP family 'QosFlow'"),
        ("ns3-name-glued-to-a-lower-case-family", set_row("gnb", "ue", "ns3.du.macPdu", kpm="ns3.du.tbNbrDl"),
         "starts with the 3GPP family 'TB'"),
        ("ns3-name-with-a-lower-case-placeholder", set_row("gnb", "cell", "ns3.du.prbReportClassId", kpm="ns3.du.qci"),
         "reuses the 3GPP placeholder 'QCI'"),
        ("3gpp-integer-typed-REAL", on_control(set_row("enb", "cell", "RRC.ConnMean", type="REAL")),
         "type REAL != the clause's INTEGER"),
        ("v17-only-name",
         as_3gpp("gnb", "cell", "ns3.du.dlPrbUsage", "RRU.PrbTotDl", "3GPP TS 28.552 V17.17.0 §5.1.1.2.1", "MAC", "%",
                 "INTEGER"),
         "V17-only name, its V20.2.0 successor is RRU.PrbDl"),
        ("v17-name-moved-to-a-successor-whose-value-check-fails",
         as_3gpp("gnb", "cell", "ns3.du.dlPrbUsage", "RRU.PrbDl", C552 + "5.1.1.2.1", "MAC", "%", "INTEGER"),
         "value check fails"),
        ("no-value-check-for-the-src",
         on_control(set_row("enb", "cell", "RRC.ConnMean", src="/cell/cuCp/numActiveUes")),
         "no value check for enb/cell /cell/cuCp/numActiveUes"),
        ("row-without-clause", on_control(drop_row_field("enb", "cell", "RRC.ConnMean", "clause")),
         "row carries no clause"),
        ("row-without-layer", drop_row_field("gnb", "ue", "ns3.imsi", "layer"), "row carries no layer"),
        ("wrong-clause", on_control(set_row("enb", "cell", "RRC.ConnMean", clause=C552 + "5.1.1.4.1")),
         "clause '3GPP TS 28.552"),
        ("node-does-not-own-the-event",
         on_control(lambda doc, reg: entry(reg, "32.425", "RRC.ConnMean").update(owningNode=["gnb"])),
         "node kind enb does not own the counted event"),
        ("int32-bound", on_control(reg_check("32.425", "RRC.ConnMean", maxValue=2**31)),
         "outside kpimon's int32 range"),
        ("int32-negative-bound", on_control(reg_check("32.425", "RRC.ConnMean", maxValue=-2**31 - 1)),
         "outside kpimon's int32 range"),
        ("int32-bound-minus-one", on_control(reg_check("32.425", "RRC.ConnMean", maxValue=-1)),
         "outside kpimon's int32 range"),
        # a pendingFix field waives nothing: it is a finding on any row, passing or failing
        ("row-carrying-pendingFix", set_row("gnb", "cell", "DRB.PdcpSduVolumeDL", pendingFix="fix"),
         "gnb/cell/35/DRB.PdcpSduVolumeDL: (8) pending: pendingFix 'fix'"),
        ("row-carrying-pendingFix-on-the-passing-control",
         on_control(set_row("enb", "cell", "RRC.ConnMean", pendingFix="fix")),
         "enb/cell/8/RRC.ConnMean: (8) pending: pendingFix 'fix'"),
        ("row-carrying-pendingFix-on-an-ns3-row", set_row("gnb", "cell", "ns3.du.macPdu", pendingFix="fix"),
         "gnb/cell/4/ns3.du.macPdu: (8) pending: pendingFix 'fix'"),
        # a row is judged by the value check of its own kind, list, src and xform
        ("DRB.PdcpSduVolumeDL-row-with-another-src-and-xform",
         set_row("gnb", "cell", "DRB.PdcpSduVolumeDL", src="/cell/cuUp/DRB.PdcpSduVolumeUL", xform="ns_to_ms_floor"),
         "gnb/cell/35/DRB.PdcpSduVolumeDL: (3) value check: no value check for gnb/cell /cell/cuUp/DRB.PdcpSduVolumeUL"),
        ("DRB.PdcpSduVolumeDL-row-with-another-xform", set_row("gnb", "cell", "DRB.PdcpSduVolumeDL", xform="ns_to_ms_floor"),
         "gnb/cell/35/DRB.PdcpSduVolumeDL: (3) xform: xform 'ns_to_ms_floor' != the value check's 'none'"),
        ("DRB.PdcpSduVolumeDL-entry-without-value-checks",
         lambda doc, reg: entry(reg, "28.552", "DRB.PdcpSduVolumeDL").update(valueChecks=[]),
         "gnb/cell/35/DRB.PdcpSduVolumeDL: (3) value check: no value check for gnb/cell /cell/cuUp/DRB.PdcpSduVolumeDL"),
        ("registry-version-not-pinned",
         lambda doc, reg: reg["documents"]["28.552"].update(version="V17.17.0"), "is not pinned to V20.2.0"),
        ("registry-source-without-line",
         reg_check("28.552", "TB.TotNbrDlInitial", source=["oran-interface@53253fe x.cc"]),
         "every source must be"),
        # null clause or layer: a present-but-null field is as absent as a missing one, on any row
        ("null-clause-on-DRB.PdcpSduVolumeDL", set_row("gnb", "cell", "DRB.PdcpSduVolumeDL", clause=None),
         "gnb/cell/35/DRB.PdcpSduVolumeDL: (1) fields: row carries no clause"),
        ("null-layer-on-DRB.PdcpSduVolumeDL", set_row("gnb", "cell", "DRB.PdcpSduVolumeDL", layer=None),
         "gnb/cell/35/DRB.PdcpSduVolumeDL: (1) fields: row carries no layer"),
        ("null-clause-on-the-passing-control", on_control(set_row("enb", "cell", "RRC.ConnMean", clause=None)),
         "enb/cell/8/RRC.ConnMean: (1) fields: row carries no clause"),
        ("null-layer-on-the-passing-control", on_control(set_row("enb", "cell", "RRC.ConnMean", layer=None)),
         "enb/cell/8/RRC.ConnMean: (1) fields: row carries no layer"),
        ("empty-clause-on-an-ns3-row", set_row("gnb", "cell", "ns3.du.macPdu", clause=""),
         "gnb/cell/4/ns3.du.macPdu: (1) fields: row carries no clause"),
        # a value check judges the value after one transform; another xform makes it judge a different number
        ("xform-only-change-on-the-passing-control",
         on_control(set_row("enb", "cell", "RRC.ConnMean", xform="ns_to_ms_floor")),
         "(3) xform: xform 'ns_to_ms_floor' != the value check's 'none'"),
        ("value-check-without-xform", drop_check_field("32.425", "RRC.ConnMean", "xform"), "missing ['xform']"),
        ("value-check-with-unknown-xform", reg_check("32.425", "RRC.ConnMean", xform="ms"), "xform 'ms' is not one of"),
        # malformed registries: findings, never an exception, and the clause checks are skipped
        ("value-check-without-holds", drop_check_field("32.425", "RRC.ConnMean", "holds"), "missing ['holds']"),
        ("value-check-without-src", drop_check_field("32.425", "RRC.ConnMean", "src"), "missing ['src']"),
        ("value-check-without-reason", drop_check_field("32.425", "RRC.ConnMean", "reason"), "missing ['reason']"),
        ("value-check-holds-not-a-boolean", reg_check("32.425", "RRC.ConnMean", holds="yes"),
         "holds must be true or false"),
        ("value-check-source-not-a-list", reg_check("32.425", "RRC.ConnMean", source="x.cc:1"),
         "source must be a list"),
        ("value-check-not-an-object",
         lambda doc, reg: entry(reg, "32.425", "RRC.ConnMean")["valueChecks"].append("x"),
         "value check 1 is not an object"),
        ("entry-without-name", lambda doc, reg: reg["entries"][0].pop("name"), "missing ['name']"),
        ("entry-not-an-object", lambda doc, reg: reg["entries"].append(None), "is not an object"),
        ("entry-valueChecks-not-a-list", entry_at(0, valueChecks="x"), "valueChecks must be a list"),
        ("entry-nameForms-not-an-object", entry_at(0, nameForms=None), "nameForms must be an object"),
        ("entry-owningNode-with-a-non-string", entry_at(0, owningNode=[{"kind": "gnb"}]), "bad owningNode"),
        ("entries-null", reg_set("entries", None), "registry: entries must be a list"),
        ("slotKinds-null", reg_set("slotKinds", None), "registry: slotKinds must be an object"),
        ("families-null", reg_set("families", None), "registry: families must be an object"),
        ("documents-null", reg_set("documents", None), "registry: documents must be an object"),
        ("slot-kind-label-zero", lambda doc, reg: reg["slotKinds"]["qci"].update(label=0),
         "slot kind qci label must be null or a non-empty string"),
        ("slot-kind-label-false", lambda doc, reg: reg["slotKinds"]["qci"].update(label=False),
         "slot kind qci label must be null or a non-empty string"),
        ("slot-kind-label-empty-list", lambda doc, reg: reg["slotKinds"]["qci"].update(label=[]),
         "slot kind qci label must be null or a non-empty string"),
        ("slot-kind-label-empty-object", lambda doc, reg: reg["slotKinds"]["qci"].update(label={}),
         "slot kind qci label must be null or a non-empty string"),
        ("slot-kind-label-blank", lambda doc, reg: reg["slotKinds"]["qci"].update(label="  "),
         "slot kind qci label must be null or a non-empty string"),
        ("maxValueBasis-one", on_control(reg_check("32.425", "RRC.ConnMean", maxValueBasis=1)),
         "an INTEGER value check needs maxValue and maxValueBasis"),
        ("totalBasis-one", on_control(lambda doc, reg: entry(reg, "32.425", "RRC.ConnMean")["nameForms"].update(totalBasis=1)),
         "nameForms needs total and totalBasis"),
        ("maxValueBasis-true", on_control(reg_check("32.425", "RRC.ConnMean", maxValueBasis=True)),
         "an INTEGER value check needs maxValue and maxValueBasis"),
        ("totalBasis-true", on_control(lambda doc, reg: entry(reg, "32.425", "RRC.ConnMean")["nameForms"].update(totalBasis=True)),
         "nameForms needs total and totalBasis"),
        ("maxValueBasis-list", on_control(reg_check("32.425", "RRC.ConnMean", maxValueBasis=["fake"])),
         "an INTEGER value check needs maxValue and maxValueBasis"),
        ("totalBasis-list", on_control(lambda doc, reg: entry(reg, "32.425", "RRC.ConnMean")["nameForms"].update(totalBasis=["fake"])),
         "nameForms needs total and totalBasis"),
        ("maxValueBasis-object", on_control(reg_check("32.425", "RRC.ConnMean", maxValueBasis={"fake": True})),
         "an INTEGER value check needs maxValue and maxValueBasis"),
        ("totalBasis-object", on_control(lambda doc, reg: entry(reg, "32.425", "RRC.ConnMean")["nameForms"].update(totalBasis={"fake": True})),
         "nameForms needs total and totalBasis"),
        ("maxValueBasis-blank", on_control(reg_check("32.425", "RRC.ConnMean", maxValueBasis=" ")),
         "an INTEGER value check needs maxValue and maxValueBasis"),
        ("totalBasis-blank", on_control(lambda doc, reg: entry(reg, "32.425", "RRC.ConnMean")["nameForms"].update(totalBasis=" ")),
         "nameForms needs total and totalBasis"),
        ("blank-string-field", on_control(reg_check("32.425", "RRC.ConnMean", reason="  ")),
         "reason must not be blank"),
        ("family-name-blank", lambda doc, reg: reg["families"]["names"].append(""),
         "families must be an object whose names is a list of strings"),
        ("placeholder-name-blank", lambda doc, reg: reg["placeholders"]["names"].append("  "),
         "placeholders must be an object whose names is a list of strings"),
        ("ns3-name-empty-component", set_row("gnb", "cell", "ns3.du.macPdu", kpm="ns3..probe"),
         "ns3 name has an empty component"),
        ("blank-family-and-empty-component",
         lambda doc, reg: [reg["families"]["names"].append(""),
                           set_row("gnb", "cell", "ns3.du.macPdu", kpm="ns3..probe")(doc, reg)] and None,
         "families must be an object whose names is a list of strings"),
        ("slot-kind-pattern-overflow",
         lambda doc, reg: reg["slotKinds"]["qci"].update(pattern="a{4294967296}"),
         "slot kind qci pattern does not compile: OverflowError"),
        ("slot-kind-pattern-too-deep",
         lambda doc, reg: reg["slotKinds"]["qci"].update(pattern="(" * 1000 + ")" * 1000),
         "slot kind qci pattern does not compile: RecursionError"),
        ("registry-not-an-object", lambda doc, reg: (doc, []), "registry: not a JSON object"),
        ("clause-checks-skipped-on-a-malformed-registry", reg_set("entries", None),
         "registry has findings: clause checks skipped"),
        # one verdict per row: duplicate checks or entries are registry findings in either array order
        ("duplicate-DRB.PdcpSduVolumeDL-check-last", dup_check("28.552", "DRB.PdcpSduVolumeDL", False, **held),
         "duplicate value check for gnb/cell /cell/cuUp/DRB.PdcpSduVolumeDL"),
        ("duplicate-DRB.PdcpSduVolumeDL-check-first", dup_check("28.552", "DRB.PdcpSduVolumeDL", True, **held),
         "duplicate value check for gnb/cell /cell/cuUp/DRB.PdcpSduVolumeDL"),
        ("duplicate-control-check-failing-one-last",
         on_control(dup_check("32.425", "RRC.ConnMean", False, holds=False)),
         "duplicate value check for enb/cell /cell/cuCp/meanRrcUes"),
        ("duplicate-control-check-failing-one-first",
         on_control(dup_check("32.425", "RRC.ConnMean", True, holds=False)),
         "duplicate value check for enb/cell /cell/cuCp/meanRrcUes"),
        ("duplicate-entry",
         lambda doc, reg: reg["entries"].append(copy.deepcopy(entry(reg, "32.425", "RRC.ConnMean"))),
         "duplicate entry 32.425 RRC.ConnMean"),
        # only the exact entry name is the bare name
        ("trailing-dot-on-the-passing-control", on_control(set_row("enb", "cell", "RRC.ConnMean", kpm="RRC.ConnMean.")),
         "enb/cell/8/RRC.ConnMean.: (4) grammar: name has an empty suffix component"),
        ("double-dot-inside-a-suffix",
         as_3gpp("enb", "ue", "ns3.cuUp.pdcpLatency", "DRB.PdcpSduDelayDl..9", C425 + "4.4.3.1", "PDCP", "ms",
                 "INTEGER"),
         "enb/ue/8/DRB.PdcpSduDelayDl..9: (4) grammar: name has an empty suffix component"),
        # a value check is the row's only when kind, list and src all match, in the row's own document
        ("value-check-in-another-list-with-the-same-src", on_control(reg_check("32.425", "RRC.ConnMean", list="ue")),
         "enb/cell/8/RRC.ConnMean: (3) value check: no value check for enb/cell /cell/cuCp/meanRrcUes"),
        ("value-check-of-another-kind-with-the-same-src", on_control(reg_check("32.425", "RRC.ConnMean", kind="gnb")),
         "enb/cell/8/RRC.ConnMean: (3) value check: no value check for enb/cell /cell/cuCp/meanRrcUes"),
        ("rows-sharing-a-src-UE-check-first", shared_src(True),
         "enb/cell/8/RRC.ConnMean: value check: value check fails: cell-list check"),
        ("rows-sharing-a-src-UE-check-last", shared_src(False),
         "enb/ue/6/RRC.ConnMean: value check: value check fails: ue-list check"),
        ("row-whose-only-matching-check-is-in-another-document", check_in_other_document,
         "gnb/cell/35/DRB.PdcpSduVolumeDL: (3) value check: no value check for gnb/cell /cell/cuUp/DRB.PdcpSduVolumeDL"),
        # want PASS: the row named by the tag must have no finding
        ("holding-check-beside-a-failing-decoy-in-another-list", decoy("list", True, False),
         (PASS, "gnb/cell/35/DRB.PdcpSduVolumeDL")),
        ("holding-check-beside-a-failing-decoy-in-another-document", decoy("document", True, False),
         (PASS, "gnb/cell/35/DRB.PdcpSduVolumeDL")),
        ("failing-check-beside-a-holding-decoy-in-another-list", decoy("list", False, True),
         "gnb/cell/35/DRB.PdcpSduVolumeDL: value check: value check fails"),
        ("failing-check-beside-a-holding-decoy-in-another-document", decoy("document", False, True),
         "gnb/cell/35/DRB.PdcpSduVolumeDL: value check: value check fails"),
        # ns3.* rows: layer none only on identity rows; any other layer fits its src section unless the row is named
        # in VENDOR_LAYER_EXCEPTIONS
        ("vendor-row-with-layer-none", set_row("gnb", "cell", "ns3.du.macPdu", layer="none"),
         "gnb/cell/4/ns3.du.macPdu: (1) fields: layer 'none' is for the identity rows only"),
        ("identity-row-with-a-layer", set_row("gnb", "cell", "ns3.nodeId", layer="MAC"),
         "gnb/cell/1/ns3.nodeId: (6) vendor: identity row: layer 'MAC' must be 'none'"),
        ("du-vendor-row-with-layer-PDCP", set_row("gnb", "cell", "ns3.du.macPdu", layer="PDCP"),
         "gnb/cell/4/ns3.du.macPdu: (6) vendor: src section 'du' does not fit layer PDCP"),
        ("du-vendor-row-with-layer-RRC-not-excepted", set_row("gnb", "cell", "ns3.du.macPdu", layer="RRC"),
         "gnb/cell/4/ns3.du.macPdu: (6) vendor: src section 'du' does not fit layer RRC"),
        ("cuUp-vendor-row-with-layer-MAC", set_row("enb", "ue", "ns3.cuUp.pdcpTxVolumeDl", layer="MAC"),
         "enb/ue/5/ns3.cuUp.pdcpTxVolumeDl: (6) vendor: src section 'cuUp' does not fit layer MAC"),
        ("cuUp-vendor-row-with-layer-RLC-not-excepted", set_row("enb", "ue", "ns3.cuUp.pdcpTxVolumeDl", layer="RLC"),
         "enb/ue/5/ns3.cuUp.pdcpTxVolumeDl: (6) vendor: src section 'cuUp' does not fit layer RLC"),
        ("cuCp-vendor-row-with-layer-PDCP", set_row("enb", "cell", "ns3.cuCp.numActiveUes", layer="PDCP"),
         "enb/cell/7/ns3.cuCp.numActiveUes: (6) vendor: src section 'cuCp' does not fit layer PDCP"),
        ("vendor-row-reading-an-identity-src", set_row("enb", "ue", "ns3.cuCp.numDrb", src="/nodeId"),
         "enb/ue/13/ns3.cuCp.numDrb: (6) vendor: src section 'nodeId' does not fit layer RRC"),
        ("excepted-row-in-another-section",
         set_row("gnb", "cell", "ns3.du.numActiveUes", src="/cell/cuUp/DRB.MeanActiveUeDl"),
         "gnb/cell/26/ns3.du.numActiveUes: (6) vendor: src section 'cuUp' does not fit layer RRC"),
        # malformed maps: findings, never an exception, and every other check skipped
        ("map-row-missing-a-required-field", lambda doc, reg: row(doc, "enb", "cell", "ns3.nodeId").pop("order"),
         "map: row 95 ('ns3.nodeId') missing ['order']"),
        ("map-not-an-object", lambda doc, reg: ([], reg), "map: not a JSON object"),
        ("map-rows-null", lambda doc, reg: doc.update(rows=None), "map: rows must be a list"),
        ("map-rows-not-a-list", lambda doc, reg: doc.update(rows={"kind": "gnb"}), "map: rows must be a list"),
        ("map-null-row", lambda doc, reg: doc["rows"].append(None), "map: row 120 is not an object"),
        ("map-non-object-row", lambda doc, reg: doc["rows"].insert(0, "row"), "map: row 0 is not an object"),
        ("map-row-kpm-null", set_row("gnb", "cell", "ns3.du.macPdu", kpm=None),
         "kpm has the wrong JSON type NoneType"),
        ("map-row-order-a-boolean", set_row("gnb", "cell", "ns3.du.macPdu", order=True),
         "order has the wrong JSON type bool"),
        ("map-findings-skip-the-other-checks", lambda doc, reg: doc.update(rows=None),
         "map has findings: structural and clause checks skipped"),
        ("structural-check-kept", set_row("gnb", "ue", "ns3.du.macVolume", kpm="ns3.du.mac_Volume"),
         "name not PrintableString-legal"),
        # Python's $ also matches before a final newline: names and slot tokens are matched in full.
        ("name-trailing-newline", set_row("gnb", "cell", "ns3.du.macPdu", kpm="ns3.du.macPdu\n"),
         "name not PrintableString-legal"),
        ("vendor-family-trailing-newline", set_row("gnb", "cell", "ns3.du.macPdu", kpm="ns3.du.QosFlow\n"),
         "name not PrintableString-legal"),
        ("vendor-placeholder-trailing-newline", set_row("gnb", "cell", "ns3.du.macPdu", kpm="ns3.du.QCI\n"),
         "name not PrintableString-legal"),
    ]
    ok = True
    errs = evaluate(base_doc, base_reg)
    good = not errs
    print("%s shipped-map-and-registry: %d findings" % ("ok  " if good else "FAIL", len(errs)))
    for e in errs: print("     ", e)
    ok &= good
    doc, reg = copy.deepcopy(base_doc), copy.deepcopy(base_reg)
    passing_control(doc, reg)
    errs = row_errs(evaluate(doc, reg), "enb/cell/8/RRC.ConnMean")
    good = not errs
    print("%s passing-control (eNB RRC.ConnMean held): %d findings on the control row" % (
        "ok  " if good else "FAIL", len(errs)))
    for e in errs: print("     ", e)
    ok &= good
    for name, mutate, want in fixtures:
        doc, reg = copy.deepcopy(base_doc), copy.deepcopy(base_reg)
        try:
            # a mutation edits the copies in place, or returns a replacement (doc, registry) tuple
            res = mutate(doc, reg)
            if isinstance(res, tuple):
                doc, reg = res
        except Exception as ex:  # noqa: BLE001 - a broken fixture fails itself, not the whole self-test
            print("FAIL %s: the fixture's mutation raised %s: %s" % (name, type(ex).__name__, ex)); ok = False; continue
        try:
            errs = evaluate(doc, reg)
        except Exception as ex:  # noqa: BLE001 - any exception is the failure this self-test exists to catch
            print("FAIL %s: the lint raised %s: %s" % (name, type(ex).__name__, ex)); ok = False; continue
        if isinstance(want, tuple):
            bad = row_errs(errs, want[1])
            print("%s %s: %s" % ("FAIL" if bad else "ok  ", name, "want no finding on %s, got %s" % (want[1], bad)
                                 if bad else "no finding on " + want[1]))
            ok &= not bad
            continue
        hit = [e for e in errs if want in e]
        print("%s %s: %s" % ("ok  " if hit else "FAIL", name, hit[0] if hit else "no finding %r in %s" % (want, errs)))
        ok &= bool(hit)
    ok &= cli_cases(lint, here, base_doc)
    print("lint-metric-map self-test: %s" % ("ok" if ok else "failed"))
    return 0 if ok else 1


def cli_cases(lint, here, base_doc):
    """main() end to end on files: a map missing a required field must exit 1 with that finding and no traceback,
    with --kpimon-enb and with --samples (both traverse the rows); the shipped map with --kpimon-enb exits 0."""
    kpimon = os.path.join(here, "..", "..", "install_patch_files", "xApps", "kpimon-go", "control",
                          "enb-kpm-measurements.json")

    def drop(field):
        def f(doc):
            next(r for r in doc["rows"] if (r["kind"], r["list"], r["order"]) == ("enb", "cell", 1)).pop(field)
        return f

    cases = [
        # (name, map mutation, extra arguments, expected exit, expected output text)
        # check_kpimon_enb reads order and check_samples reads src: each must be stopped before it reads
        ("cli-missing-order-with-kpimon-enb", drop("order"), ["--kpimon-enb", kpimon], 1,
         "FAIL map: row 95 ('ns3.nodeId') missing ['order']"),
        ("cli-missing-src-with-samples", drop("src"), ["--samples", "{samples}"], 1,
         "FAIL map: row 95 ('ns3.nodeId') missing ['src']"),
        ("cli-shipped-map-with-kpimon-enb", lambda doc: None, ["--kpimon-enb", kpimon], 0, '"findings": 0'),
    ]
    ok = True
    with tempfile.TemporaryDirectory() as d:
        samples = os.path.join(d, "samples.ndjson")
        with open(samples, "w") as f:
            f.write(json.dumps({"type": "hello", "kind": "enb"}) + "\n" +
                    json.dumps({"type": "sample", "nodeId": 1, "simTimeNs": 0, "seq": 0, "ues": []}) + "\n")
        for name, mutate, extra, want_rc, want in cases:
            doc = copy.deepcopy(base_doc)
            mutate(doc)
            path = os.path.join(d, name + ".json")
            with open(path, "w") as f:
                json.dump(doc, f)
            out = io.StringIO()
            try:
                with contextlib.redirect_stdout(out):
                    rc = lint.main(["lint-metric-map.py", path] + [a.replace("{samples}", samples) for a in extra])
            except Exception as ex:  # noqa: BLE001 - a traceback is the failure these cases exist to catch
                print("FAIL %s: main() raised %s: %s" % (name, type(ex).__name__, ex)); ok = False; continue
            good = rc == want_rc and want in out.getvalue()
            print("%s %s: exit %s%s" % ("ok  " if good else "FAIL", name, rc,
                                        "" if good else ", want %s and %r in %r" % (want_rc, want, out.getvalue())))
            ok &= good
    return ok
