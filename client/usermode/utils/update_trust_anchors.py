import os
import os.path

SPACES_PER_TAB = 4

trust_anchors = []

afrinic_path = "afrinic.der"
apnic_path = "apnic.der"
lacnic_path = "lacnic.der"
ripe_path = "ripe.der"
arin_path = "arin.der"

os.system("rsync rsync://rpki.afrinic.net/repository/AfriNIC.cer ./" + afrinic_path)
os.system("rsync rsync://rpki.apnic.net/repository/APNIC.cer ./" + apnic_path)
os.system("rsync rsync://repository.lacnic.net/rpki/lacnic/RTA_LACNIC_RPKI.cer ./" + lacnic_path)
os.system("rsync rsync://rpki.ripe.net/ta/ripe-ncc-ta.cer ./" + ripe_path)
os.system("rsync rsync://rpki-pilot.arin.net:10873/certrepo//e8/29afd2-319c-428f-b6b0-3528a7d24dcd/1/4789Xt9H2ltHuAXdrQ6GWXWH2Ao.cer ./" + arin_path)

if os.path.exists(afrinic_path):
    fh = open(afrinic_path, "rb")
    afrinic = fh.read()
    fh.close()
    trust_anchors.append(afrinic)
    os.remove(afrinic_path)
if os.path.exists(apnic_path):
    fh = open(apnic_path, "rb")
    apnic = fh.read()
    fh.close()
    trust_anchors.append(apnic)
    os.remove(apnic_path)
if os.path.exists(lacnic_path):
    fh = open(lacnic_path, "rb")
    lacnic = fh.read()
    fh.close()
    trust_anchors.append(lacnic)
    os.remove(lacnic_path)
if os.path.exists(ripe_path):
    fh = open(ripe_path, "rb")
    ripe = fh.read()
    fh.close()
    trust_anchors.append(ripe)
    os.remove(ripe_path)
if os.path.exists(arin_path):
    fh = open(arin_path, "rb")
    arin = fh.read()
    fh.close()
    trust_anchors.append(arin)
    os.remove(arin_path)

def _format_bytes(b):
    result = "b'"
    i = 0
    while i < len(b):
        result += "\\x%02x" % b[i]
        i += 1
    result += "'"
    return result

trust_anchors = list(map(_format_bytes, trust_anchors))
fh = open("certificates.py", "w")
fh.write("trust_anchors = [\n")
i = 0
for trust_anchor in trust_anchors:
    fh.write(SPACES_PER_TAB * " ")
    fh.write(trust_anchor)
    i += 1
    if i < len(trust_anchors):
        fh.write(",\n")
fh.write("\n]")
fh.close()