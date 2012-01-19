from packet import IPv6, ICMPv6_NDP_RSASignature
#import security

# see RFC 3971
CGA_MESSAGE_TYPE_TAG = b"\x08\x6F\xCA\x5E\x10\xB2\x00\xC9\x9C\x8C\xE0\x01\x64\x27\x7C\x08"
CERT_PATH = './test/example_data/router0/router0.cer'

class Shared(object):

    def new_packet(self, data, accept_callback, reject_callback):
        packet = IPv6(data)
        signed_data = bytearray(CGA_MESSAGE_TYPE_TAG)
        signed_data.extend(packet["source_addr"])
        signed_data.extend(packet["destination_addr"])
        signed_data.extend(packet.payload.binary)

        rsa_option = None
        for option in packet.payload.options:
            if isinstance(option, ICMPv6_NDP_RSASignature):
                rsa_option = option
                break
            signed_data.extend(option.binary)

        if rsa_option is None:
            print("Unsinged RA --> accept")
            accept_callback()
            return

        if security.verify_signature(CERT_PATH, signed_data, rsa_option["digital_signature"]):
            print("Valid signature --> accept")
            accept_callback()
        else:
            print("Invalid Signature --> reject")
            reject_callback()
