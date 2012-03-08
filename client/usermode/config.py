# MODE - valid options are:
#   - "mixedMode": process secured and unsecured RAs, but unsecured RAs
#                  cannot overwrite secured RAs
#   - "onlySend":  process only secured RAs, unsecured RAs will be blocked
#   - "noSend":    process all RAs

MODE = "mixedMode"

# ADDITIONAL_TRUST_ANCHORS
# list of DER encoded certificates that should be used as trust anchors
# in addition to the standart trust anchors that ship with TrustRouter

ADDITIONAL_TRUST_ANCHORS = []