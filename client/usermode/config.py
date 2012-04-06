# MODE - valid options are:
#   - "mixedMode": process secured and unsecured RAs, but unsecured RAs
#                  cannot overwrite secured RAs
#   - "onlySend":  process only secured RAs, unsecured RAs will be blocked
#   - "noUnsecuredAfterSecured": reject all unsecured RAs on an interface 
#                  after receiving the first secured RA on that interface
#   - "noSend":    process all RAs

MODE = "mixedMode"

# ADDITIONAL_TRUST_ANCHORS
# list of paths to DER encoded certificates that should be used as trust anchors
# in addition to the standard trust anchors that ship with TrustRouter

ADDITIONAL_TRUST_ANCHORS = []

# NDPROTECTOR_COMPATIBILITY
# enable compatibility for NDprotecotor (http://amnesiak.org/NDprotector/)
NDPROTECTOR_COMPATIBILITY = False