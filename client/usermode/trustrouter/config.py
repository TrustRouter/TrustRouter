
MODE_MIXED = 0
MODE_ONLY_SEND = 1
MODE_NO_SEND = 2
MODE_NO_UNSECURED_AFTER_SECURED = 3


class Config(object):

    MODE_TRANSLATION = {
        "mixedMode" : MODE_MIXED,
        "onlySend" : MODE_ONLY_SEND,
        "noSend" : MODE_NO_SEND,
        "noUnsecuredAfterSecured" : MODE_NO_UNSECURED_AFTER_SECURED
    }

    def __init__(self, config, error_log):
        self.mode = self._mode(config, error_log)
        self.trust_anchors = self._trust_anchor(config, error_log)


    def _mode(self, config, log):
        mode = getattr(config, "MODE", None)
        if mode in self.MODE_TRANSLATION:
            return self.MODE_TRANSLATION[mode]
        elif mode is not None:
            log("Invalid config option for MODE: %s. Using default." % mode)
        return MODE_MIXED

    def _trust_anchor(self, config, log):
        cert_list = getattr(config, "ADDITIONAL_TRUST_ANCHORS", None)
        if isinstance(cert_list, list):
            filtered_list = [item for item in cert_list if isinstance(item, bytes)]
            if len(filtered_list) != len(cert_list):
                log("Invalid config option for ADDITIONAL_TRUST_ANCHORS: Ignoring all non-byte strings.")
            return filtered_list
        elif cert_list is not None:
            log("Invalid config option for ADDITIONAL_TRUST_ANCHORS: Must be a list.")
        return []