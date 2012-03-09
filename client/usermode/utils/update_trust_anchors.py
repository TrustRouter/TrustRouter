import os
import os.path

trust_anchors = {}

def get_trust_anchors():
    print("getting trust anchors from rsync-repositories...")
    afrinic_path = "afrinic.der"
    apnic_path = "apnic.der"
    lacnic_path = "lacnic.der"
    ripe_path = "ripe.der"
    arin_path = "arin.der"

    print("getting afrinic certificate...")
    os.system("rsync rsync://rpki.afrinic.net/repository/AfriNIC.cer ./" + afrinic_path)
    if os.path.exists(afrinic_path):
        fh = open(afrinic_path, "rb")
        afrinic = fh.read()
        fh.close()
        trust_anchors["afrinic"] = afrinic
        os.remove(afrinic_path)
        print("OK.")
    else:
        print("Failure!")

    print("getting apnic certificate...")
    os.system("rsync rsync://rpki.apnic.net/repository/APNIC.cer ./" + apnic_path)
    if os.path.exists(apnic_path):
        fh = open(apnic_path, "rb")
        apnic = fh.read()
        fh.close()
        trust_anchors["apnic"] = apnic
        os.remove(apnic_path)
        print ("OK.")
    else:
        print("Failure!")
    
    print("getting lacnic certificate...")
    os.system("rsync rsync://repository.lacnic.net/rpki/lacnic/RTA_LACNIC_RPKI.cer ./" + lacnic_path)
    if os.path.exists(lacnic_path):
        fh = open(lacnic_path, "rb")
        lacnic = fh.read()
        fh.close()
        trust_anchors["lacnic"] = lacnic
        os.remove(lacnic_path)
        print("OK.")
    else:
        print("Failure!")

    print("getting ripe certificate...")
    os.system("rsync rsync://rpki.ripe.net/ta/ripe-ncc-ta.cer ./" + ripe_path)
    if os.path.exists(ripe_path):
        fh = open(ripe_path, "rb")
        ripe = fh.read()
        fh.close()
        trust_anchors["ripe"] = ripe
        os.remove(ripe_path)
        print("OK.")
    else:
        print("Failure!")

    print("getting arin certificate...")
    os.system("rsync rsync://rpki-pilot.arin.net:10873/certrepo//e8/29afd2-319c-428f-b6b0-3528a7d24dcd/1/4789Xt9H2ltHuAXdrQ6GWXWH2Ao.cer ./" + arin_path)
    if os.path.exists(arin_path):
        fh = open(arin_path, "rb")
        arin = fh.read()
        fh.close()
        trust_anchors["arin"] = arin
        os.remove(arin_path)
        print("OK.")
    else:
        print("Failure!")

    return trust_anchors

def _format_bytes(b):
    result = "b'"
    i = 0
    while i < len(b):
        result += "\\x%02x" % b[i]
        i += 1
    result += "'"
    return result


if __name__ == "__main__":
    trust_anchors = get_trust_anchors()
    fh = open("certificates.py", "w")
    for key in trust_anchors.keys():
        fh.write("%s = %s\n" % (key, _format_bytes(trust_anchors[key])))
    trust_anchors_string = "%s" % list(trust_anchors.keys())
    trust_anchors_string = trust_anchors_string.replace("'", "")
    trust_anchors_string = trust_anchors_string.replace('"', "")
    fh.write("trust_anchors = %s\n" % trust_anchors_string)
    fh.close()