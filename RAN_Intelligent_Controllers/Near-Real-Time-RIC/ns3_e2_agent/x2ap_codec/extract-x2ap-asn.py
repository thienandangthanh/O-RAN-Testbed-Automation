"""Extract the X2AP ASN.1 modules of 3GPP TS 36.423 v19.1.0 from `pdftotext -layout` output: the text between each
'-- ASN1START' and '-- ASN1STOP' marker, without the page header and footer lines, and with a comment that the PDF
wrapped onto the next line (a column-0 line that is not an assignment, closing brace or comment, an identifier split at a
hyphen, or a '--' marker split across the wrap) joined back."""
import re, sys

src, dst = sys.argv[1], sys.argv[2]
t = open(src, encoding="utf-8").read()
noise = re.compile(r"^\s*(ETSI|ETSI TS 136 423 V19\.1\.0 \(2026-02\)(\s+\d+)?|"
                   r"3GPP TS 36\.423 version 19\.1\.0 Release 19(\s+\d+(\s+ETSI TS 136 423 V19\.1\.0 \(2026-02\))?)?)\s*$")
out = []
for b in re.findall(r"-- ASN1START(.*?)-- ASN1STOP", t, re.S):
    lines = [l.replace("\f", "") for l in b.split("\n")]
    lines = [l for l in lines if not noise.match(l)]
    j = []
    for l in lines:
        if j and re.search(r"[A-Za-z0-9]-$", j[-1].rstrip()) and re.match(r"[A-Za-z0-9]", l):
            j[-1] = j[-1].rstrip() + l  # an identifier split at a hyphen
        elif j and re.search(r"[^-]-$", j[-1].rstrip()) and l.startswith("-"):
            j[-1] = j[-1].rstrip() + l  # a '--' comment marker split across the wrap
        elif (j and len(re.findall(r"--", j[-1])) % 2 == 1 and l and not l[0].isspace() and "::=" not in l
                and not l.startswith("--") and not l.startswith("}")):
            j[-1] += " " + l
        else:
            j.append(l)
    out.append("\n".join(j))
open(dst, "w", encoding="utf-8").write("\n\n".join(out) + "\n")
