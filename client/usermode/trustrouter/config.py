
import os.path

# Mode constants:
#   - MODE_MIXED: process secured and unsecured RAs, but unsecured RAs
#                 cannot overwrite secured RAs
#   - MODE_ONLY_SEND: process only secured RAs, unsecured RAs will be blocked
#   - MODE_NO_UNSECURED_AFTER_SECURED: reject all unsecured RAs on an interface 
#                   after receiving the first secured RA on that interface
#   - MODE_NO_SEND: process all RAs
MODE_MIXED = 0
MODE_ONLY_SEND = 1
MODE_NO_SEND = 2
MODE_NO_UNSECURED_AFTER_SECURED = 3


class Config(object):

    MODE_TRANSLATION = {
        "mixedmode" : MODE_MIXED,
        "onlysend" : MODE_ONLY_SEND,
        "nosend" : MODE_NO_SEND,
        "nounsecuredaftersecured" : MODE_NO_UNSECURED_AFTER_SECURED
    }

    def __init__(self, config, error_log):
        self.mode = self._mode(config, error_log)
        self.trust_anchors = self._trust_anchors(config, error_log)
        self.ndprotector_compatibility = self._ndprotector_compatibility(config, error_log)


    def _mode(self, config, log):
        mode = getattr(config, "MODE", None)
        if mode is None:
            return MODE_MIXED
        mode_lower = mode.lower()
        if mode_lower in self.MODE_TRANSLATION:
            return self.MODE_TRANSLATION[mode_lower]
        log("Invalid config option for MODE: %s. Using default." % mode)
        

    def _trust_anchors(self, config, log):
        cert_list = getattr(config, "ADDITIONAL_TRUST_ANCHORS", None)
        if isinstance(cert_list, list):
            valid_paths = set([item for item in cert_list if os.path.exists(item)])
            invalid_paths = set(cert_list).difference(valid_paths)
            if len(invalid_paths) > 0:
                log("Invalid config option for ADDITIONAL_TRUST_ANCHORS, path does not point to a file: %s" % invalid_paths)
            result = []
            for path in valid_paths:
                fh = open(path, "rb")
                cert = fh.read()
                fh.close()
                result.append(cert)
            return result
        elif cert_list is not None:
            log("Invalid config option for ADDITIONAL_TRUST_ANCHORS: Must be a list.")
        return []


    def _ndprotector_compatibility(self, config, log):
        value = getattr(config, "NDPROTECTOR_COMPATIBILITY", None)
        if isinstance(value, bool):
            return value
        elif value is not None:
            log("Invalid config option for NDPROTECTOR_COMPATIBILITY: Must be a bool.")
        return True 