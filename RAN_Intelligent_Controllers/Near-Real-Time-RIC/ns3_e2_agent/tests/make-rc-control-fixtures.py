"""make-rc-control-fixtures.py: write tests/fixtures/rc-control-nrcgi.hex, RIC CONTROL header and message octets
encoded per X.691 by the independent codec (harness tools/asn1-indep, pycrate), one line "<id> <header hex>
<message hex>". rc-control-test reads the expectation from the id.

Run inside the asn1-indep image (it has e2indep on the path), from this directory:
    podman run --rm -i --network=none localhost/asn1-indep:<tag> python3 - < make-rc-control-fixtures.py \
        > fixtures/rc-control-nrcgi.hex

Positives, id "s5a3-x2ap<X>-mn<M hex>-gnb<n>": Control Header Format 1, CONTROL Style 5 "Dual Connectivity
control", action 3 "DC PSCell Change control" (E2SM-RC v03.00 7.6.6.1), UE ID en-gNB-UEID {m-eNB-UE-X2AP-ID X,
globalENB-ID {PLMN 00F110, macro eNB ID M}} and no optional member; Control Message Format 1 with RAN parameters
1 > 2 > 3 > 4 (8.4.6.3), parameter 4 = the APER NR-CGI (E2SM common) of PLMN 00F110 and NR Cell Identity = gNB ID n
(32 bits) || cell part 1.
Negatives, the positive's message with one header change: "invalid-*" must be refused control-message-invalid,
"unsupported-*" action-not-supported.
"""
from e2indep import e2sm_rc
from e2indep.codec import bitstr, encode
from e2indep_gen import E2SM_RC_v0200

PLMN = bytes.fromhex("00f110")


def nr_cgi(gnb_id):
    return encode(E2SM_RC_v0200.E2SM_COMMON_IEs.NR_CGI,
                  {"pLMNIdentity": PLMN, "nRCellIdentity": ((gnb_id << 4) | 1, 36)})


def message(gnb_id):
    target = {"id": 4, "value": ("valueOctS", nr_cgi(gnb_id)), "key": False}
    return e2sm_rc.control_message([{"id": 1, "structure": [{"id": 2, "structure": [{"id": 3, "structure": [target]}]}]}])


def en_gnb(x2, macro, plmn=PLMN, enb_id=None, **optional):
    kind, val = e2sm_rc.ue_id_en_gnb(x2, plmn, macro)
    if enb_id is not None:
        val["globalENB-ID"]["eNB-ID"] = enb_id
    val.update(optional)
    return (kind, val)


def line(name, hdr, gnb):
    print("%s %s %s" % (name, hdr.hex(), message(gnb).hex()))


for x2, macro, gnb in ((5, 0x00001, 3), (4095, 0xFFFFF, 2), (0, 0x00001, 2)):
    line("s5a3-x2ap%d-mn%05X-gnb%d" % (x2, macro, gnb), e2sm_rc.control_header(en_gnb(x2, macro), 5, 3), gnb)

line("invalid-gnb-ueid", e2sm_rc.control_header(e2sm_rc.ue_id_gnb(1, PLMN, 1, 0, 0, [1], [1]), 5, 3), 3)
line("invalid-x2ap-id-extension", e2sm_rc.control_header(en_gnb(5, 1, **{"m-eNB-UE-X2AP-ID-Extension": 1}), 5, 3), 3)
line("invalid-gnb-cu-ue-f1ap-id", e2sm_rc.control_header(en_gnb(5, 1, **{"gNB-CU-UE-F1AP-ID": 1}), 5, 3), 3)
line("invalid-plmn-00f220", e2sm_rc.control_header(en_gnb(5, 1, plmn=bytes.fromhex("00f220")), 5, 3), 3)
line("invalid-home-enb-id", e2sm_rc.control_header(en_gnb(5, 1, enb_id=("home-eNB-ID", bitstr(1, 28))), 5, 3), 3)
line("invalid-control-decision", e2sm_rc.control_header(en_gnb(5, 1), 5, 3, decision="accept"), 3)
line("unsupported-s3a1-gnb-ueid", e2sm_rc.control_header(e2sm_rc.ue_id_gnb(1, PLMN, 1, 0, 0, [1], [1]), 3, 1), 3)
line("unsupported-s3a1-en-gnb-ueid", e2sm_rc.control_header(en_gnb(5, 1), 3, 1), 3)
line("unsupported-s5a4", e2sm_rc.control_header(en_gnb(5, 1), 5, 4), 3)
